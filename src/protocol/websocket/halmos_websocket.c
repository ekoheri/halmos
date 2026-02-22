#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_websocket.h"
#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_log.h"
#include "halmos_tls.h"
#include "halmos_http1_header.h" // Untuk akses struct RequestHeader
#include "halmos_event_loop.h"   // Untuk rearm_epoll_oneshot

#include "halmos_ws_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <arpa/inet.h>   // Untuk htons, ntohs
#include <endian.h>      // Untuk be64toh, htobe64

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define MAX_WS_PAYLOAD (10 * 1024 * 1024)

// halmos_global.c atau di tempat yang sesuai
static bool ws_fd_map[65536]; 

/* ===================================================================
 * 1. INTERNAL HELPERS (STATIC)
 * Fungsi-fungsi pembantu yang hanya dikenal di dalam file ini.
 * =================================================================== */

/**
 * Base64 encode manual agar tidak ketergantungan OpenSSL BIO yang lambat.
 */
static char* ws_base64_encode(const unsigned char *input, int length);

/**
 * Membangun kunci jawaban "Sec-WebSocket-Accept" sesuai RFC 6455.
 */
static char* ws_create_accept_key(const char *client_key);

/**
 * Wrapper recv yang mendukung TLS dan Plaintext secara transparan.
 */
static ssize_t ws_low_level_recv(int fd, void *buf, size_t len);

static void halmos_ws_send_pong(int sock_client);

static void* halmos_ws_maintenance_run(void *arg);

static void halmos_ws_start_maintenance();

/* ===================================================================
 * 2. HANDSHAKE & UPGRADE
 * Bagian yang mengubah koneksi HTTP menjadi WebSocket.
 * =================================================================== */

/**
 * ws_is_upgrade_request
 * Mengecek apakah request HTTP ini valid untuk di-upgrade ke WebSocket.
 * RFC 6455 mewajibkan:
 * 1. Method harus GET.
 * 2. Header Upgrade harus berisi "websocket".
 * 3. Header Connection harus berisi "Upgrade".
 */

bool halmos_is_websocket_fd(int fd) {
    if (fd >= 0 && fd < 65536) return ws_fd_map[fd];
    return false;
}

void halmos_set_websocket_fd(int fd, bool status) {
    if (fd >= 0 && fd < 65536) ws_fd_map[fd] = status;
}

bool ws_is_upgrade_request(RequestHeader *req) {
    //fprintf(stderr, "[DEBUG-WS] Memeriksa Upgrade... Method: %s, Flag: %d\n", 
    //        req->method, req->is_upgrade);

    // 1. Method wajib GET
    if (strcasecmp(req->method, "GET") != 0) {
        //fprintf(stderr, "[DEBUG-WS] Gagal: Method bukan GET tapi %s\n", req->method);
        return false;
    }

    // 2. Flag upgrade dari parser wajib TRUE
    if (!req->is_upgrade) {
        //fprintf(stderr, "[DEBUG-WS] Gagal: is_upgrade flag is FALSE\n");
        return false;
    }

    // 3. Key wajib ada (Hasil tangkapan parser)
    if (req->ws.key == NULL || req->ws.key[0] == '\0') {
        //fprintf(stderr, "[DEBUG-WS] Gagal: Sec-WebSocket-Key tidak ditemukan\n");
        return false;
    }

    // Kalau sudah sampai sini dan req->is_upgrade tadi YES, berarti sah!
    //fprintf(stderr, "[DEBUG-WS] MATCH! FD siap Upgrade. Key: %s\n", req->ws.key);
    return true;
}

/**
 * Mengirim balasan HTTP 101 Switching Protocols.
 */
int ws_upgrade_handshake(int sock_client, RequestHeader *req) {
    if (!req->ws.key) return -1;

    char *accept_key = ws_create_accept_key(req->ws.key);
    if (!accept_key) return -1;

    char response[512];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Server: Halmos-Savage/2.1\r\n\r\n",
        accept_key);

    ssize_t sent = 0;
    SSL *ssl = get_ssl_for_fd(sock_client);
    
    // Gunakan loop kecil atau handling EAGAIN jika perlu
    // Tapi untuk handshake yang cuma 200-an byte, biasanya sekali kirim habis
    if (ssl) {
        sent = SSL_write(ssl, response, len);
    } else {
        sent = send(sock_client, response, len, MSG_NOSIGNAL);
    }

    free(accept_key);

    if (sent <= 0) {
        // Cek apakah memang error atau cuma disuruh nunggu (EAGAIN)
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
             // Di Halmos, ini berarti kita harus rearm. 
             // Tapi handshake biasanya kecil, kalau ini gagal, koneksi emang bermasalah.
             return -1; 
        }
        return -1;
    }

    // --- DI SINI TEMPATNYA ---
    // Karena ws_upgrade_handshake sudah punya akses ke 'ssl' via get_ssl_for_fd,
    // Kita langsung daftarkan ke buku alamat.
    int slot = ws_registry_add(sock_client, ssl);
    
    if (slot != -1) {
        write_log("[WS-REGISTRY] FD %d successfully registered in slot %d", sock_client, slot);
        ws_registry_broadcast("{\"event\": \"new_user\", \"msg\": \"Seseorang baru saja bergabung!\"}");
    } else {
        write_log("[WS-REGISTRY] ERROR: Failed to register FD %d (Registry Full?)", sock_client);
        // Tergantung kebijakan lu, kalau penuh apa mau ditendang? 
        // Sementara biarkan saja dulu untuk testing.
    }

    write_log("[WS] Handshake OK on FD %d", sock_client);
    return 0;
}

/* ===================================================================
 * 3. FRAME RECEIVER (THE ENGINE)
 * Mesin utama pembongkar frame WebSocket secara non-blocking.
 * =================================================================== */

/**
 * halmos_ws_recv_frame
 * Membedah binary frame WebSocket sesuai RFC 6455.
 * Mengembalikan: 
 * - 0: Sukses (payload terisi)
 * - 1: Data belum lengkap (EAGAIN), perlu rearm epoll
 * - -1: Error fatal / Koneksi ditutup
 */
int halmos_ws_recv_frame(int fd, int *opcode, unsigned char **payload, size_t *out_len) {
    unsigned char header[2];
    
    // 1. BACA 2 BYTE PERTAMA (HEADER DASAR)
    ssize_t n = ws_low_level_recv(fd, header, 2);
    if (n < 2) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        return -1; 
    }

    // Byte 1: [FIN(1) | RSV(3) | Opcode(4)]
    // Byte 2: [MASK(1) | PayloadLen(7)]
    *opcode = header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    // 2. DETEKSI PANJANG PAYLOAD (EXTENDED)
    if (payload_len == 126) {
        uint16_t ext_len;
        if (ws_low_level_recv(fd, &ext_len, 2) < 2) return -1;
        payload_len = ntohs(ext_len);
    } else if (payload_len == 127) {
        uint64_t ext_len;
        if (ws_low_level_recv(fd, &ext_len, 8) < 8) return -1;
        payload_len = be64toh(ext_len); 
    }

    // 3. AMBIL MASKING KEY (WAJIB DARI CLIENT)
    uint8_t mask[4];
    if (masked) {
        if (ws_low_level_recv(fd, mask, 4) < 4) return -1;
    }

    // 4. ALOKASI & BACA ISI PESAN (PAYLOAD)
    // Kita tambah 1 byte untuk null-terminator biar aman buat JSON

    if (payload_len > MAX_WS_PAYLOAD) {
        write_log_error("[SECURITY] FD %d kirim payload kegedean (%zu bytes). TENDANG!", fd, payload_len);
        return -1; // Trigger disconnect di dispatcher
    }
    
    *payload = malloc(payload_len + 1);
    if (!(*payload)) return -1;

    size_t total_read = 0;
    while (total_read < payload_len) {
        ssize_t r = ws_low_level_recv(fd, (*payload) + total_read, payload_len - total_read);
        if (r > 0) {
            total_read += r;
        } else {
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Untuk kesederhanaan, jika payload kepotong, kita tunggu bentar (usleep) 
                // atau lu bisa implementasiin state-machine yang lebih kompleks nanti.
                usleep(1000); 
                continue; 
            }
            free(*payload);
            return -1;
        }
    }
    (*payload)[payload_len] = '\0';
    *out_len = payload_len;

    // 5. UNMASKING DATA (XOR LOGIC)
    // Browser wajib nge-mask data, kita wajib buka topengnya.
    if (masked) {
        for (size_t i = 0; i < payload_len; i++) {
            (*payload)[i] ^= mask[i % 4];
        }
    }

    return 0; // Frame sukses diproses
}


/* ===================================================================
 * 4. DISPATCHER & LOGIC
 * Jembatan antara Worker Thread dan Bisnis Logik (JSON).
 * =================================================================== */

/**
 * halmos_ws_dispatch
 * Entry point utama yang dipanggil oleh Worker Thread saat Epoll mendeteksi data masuk.
 * Return 1: Tetap hidup (Rearm Epoll), 0: Tutup koneksi (Cleanup).
 */
int halmos_ws_dispatch(int sock_client) {
    int opcode;
    unsigned char *payload = NULL;
    size_t payload_len = 0;

    // 1. Ambil data frame (Memanggil fungsi bedah frame kita sebelumnya)
    int res = halmos_ws_recv_frame(sock_client, &opcode, &payload, &payload_len);

    if (res == 1) {
        // Data belum lengkap (EAGAIN), suruh worker balik lagi nanti
        return 1; 
    }

    if (res < 0) {
        // Error fatal atau koneksi diputus secara paksa oleh client
        write_log("[WS] Frame error or connection lost on FD %d", sock_client);
        return 0; 
    }

    // 2. LOGIKA BERDASARKAN OPCODE (RFC 6455)
    switch (opcode) {
        case WS_OP_TEXT:
            // Pesan teks (Biasanya JSON untuk aplikasi lu)
            if (payload) {
                halmos_ws_on_message(sock_client, payload, payload_len);
            }
            break;

        case WS_OP_BIN:
            // Pesan binary (Jika lu kirim gambar/file lewat WS)
            write_log("[WS] Received binary frame (%zu bytes) on FD %d", payload_len, sock_client);
            break;

        case WS_OP_PING:
            // Browser nanya: "Masih hidup gak?" -> Kita harus bales PONG
            write_log("[WS] Ping received. Sending Pong to FD %d", sock_client);
            halmos_ws_send_pong(sock_client); 
            break;

        case WS_OP_PONG:
            // Balasan dari Ping yang pernah kita kirim (Heartbeat)
            ws_registry_update_activity(sock_client);
            break;

        case WS_OP_CLOSE:
            // Client minta cerai baik-baik
            write_log("[WS] Close frame received from FD %d", sock_client);
            if (payload) free(payload);
            return 0; // Trigger cleanup di manager

        default:
            write_log("[WS] Unknown Opcode 0x%x on FD %d", opcode, sock_client);
            break;
    }

    // 3. CLEANUP & REARM
    if (payload) {
        free(payload); // Bebaskan payload karena sudah diproses di on_message
    }

    return 1; // Return 1 agar FD di-rearm oleh epoll (ONESHOT)
}

/**
 * halmos_ws_on_message
 * Di sinilah logika aplikasi berjalan. 
 * Menerima string/payload yang sudah di-unmask dan siap diproses.
 */
void halmos_ws_on_message(int sock_client, unsigned char *data, size_t len) {
    if (len == 0 || data == NULL) return;

    // 1. Parsing JSON menggunakan Tokener (Lebih aman untuk data stream)
    struct json_tokener *tok = json_tokener_new();
    struct json_object *parsed_json = json_tokener_parse_ex(tok, (const char *)data, len);

    if (parsed_json == NULL) {
        write_log_error("[WS-JSON] Malformed JSON received on FD %d", sock_client);
        json_tokener_free(tok);
        return;
    }

    // 2. Akses Header berdasarkan kamus ws_cfg
    struct json_object *header_obj = NULL;
    if (json_object_object_get_ex(parsed_json, ws_cfg.envelope.header, &header_obj)) {
        
        struct json_object *action_obj = NULL;
        struct json_object *dst_obj = NULL;
        struct json_object *app_obj = NULL;

        // Ambil field rute dari dalam header
        json_object_object_get_ex(header_obj, ws_cfg.keys.action, &action_obj);
        json_object_object_get_ex(header_obj, ws_cfg.keys.to, &dst_obj);
        json_object_object_get_ex(header_obj, ws_cfg.keys.app, &app_obj);

        // VALIDASI: Pastikan action dan target ada isinya sebelum diproses
        if (action_obj && dst_obj) {
            const char *action = json_object_get_string(action_obj);
            const char *target = json_object_get_string(dst_obj);
            
            // App ID opsional, kalau NULL kasih string kosong atau "DEFAULT"
            const char *app_id = app_obj ? json_object_get_string(app_obj) : "GLOBAL";

            write_log("[WS] Route: App=%s, Action=%s, Target=%s", app_id, action, target);

            // 3. LOGIKA EKSEKUSI
            if (strcmp(action, "PUB") == 0) {
                // Publish pesan ke topik/grup
                ws_registry_publish(app_id, target, (const char *)data); 
            } 
            else if (strcmp(action, "SUB") == 0) {
                // Daftarkan socket ke topik/grup
                ws_registry_add_to_topic(sock_client, app_id, target);
            }
            else if (strcmp(action, "REQ") == 0) {
                // Jika REQ, biasanya butuh body/payload-nya
                struct json_object *payload_obj = NULL;
                json_object_object_get_ex(parsed_json, ws_cfg.envelope.payload, &payload_obj);
                
                // Lempar ke fungsi backend FastCGI lu
                // halmos_bridge_to_fastcgi(sock_client, app_id, target, payload_obj);
            }
        } else {
            write_log_error("[WS] Missing routing keys in header on FD %d", sock_client);
        }
    } else {
        write_log_error("[WS] Envelope header '%s' not found on FD %d", ws_cfg.envelope.header, sock_client);
    }

    // 4. CLEANUP (Wajib!)
    json_object_put(parsed_json);
    json_tokener_free(tok);
}


/* ===================================================================
 * 5. SENDER
 * Fungsi untuk membungkus data menjadi frame WebSocket dan mengirimnya.
 * =================================================================== */

/**
 * halmos_ws_send_text
 * Membungkus string teks ke dalam frame WebSocket dan mengirimkannya.
 * Mendukung otomatisasi panjang payload (Small, Medium, Large).
 */
int halmos_ws_send_text(int sock_client, const char *text) {
    if (!text) return -1;

    size_t len = strlen(text);
    unsigned char frame_header[10]; // Maksimal header WS adalah 10 byte
    int header_idx = 0;

    // 1. BYTE 1: FIN=1, RSV=0, OPCODE=1 (Text)
    // 0x80 (10000000) | 0x01 (00000001) = 0x81
    frame_header[header_idx++] = 0x81;

    // 2. BYTE 2 & EXTENDED LENGTH
    // Ingat: Server-to-Client MASK bit (bit pertama Byte 2) HARUS 0.
    if (len <= 125) {
        // Small Frame: Cukup 7 bit untuk panjang data
        frame_header[header_idx++] = (uint8_t)len;
    } 
    else if (len <= 65535) {
        // Medium Frame: Byte 2 diisi 126, lalu 2 byte berikutnya adalah panjangnya
        frame_header[header_idx++] = 126;
        uint16_t net_len = htons((uint16_t)len); // Convert ke Big-Endian
        memcpy(&frame_header[header_idx], &net_len, 2);
        header_idx += 2;
    } 
    else {
        // Large Frame: Byte 2 diisi 127, lalu 8 byte berikutnya adalah panjangnya
        frame_header[header_idx++] = 127;
        uint64_t net_len = htobe64((uint64_t)len); // Convert ke Big-Endian (64-bit)
        memcpy(&frame_header[header_idx], &net_len, 8);
        header_idx += 8;
    }

    // 3. PENGIRIMAN (TRANSPARENT TLS/PLAIN)
    SSL *ssl = get_ssl_for_fd(sock_client);
    
    // Kita kirim header dulu, baru datanya (bisa pakai writev kalau mau lebih kenceng)
    if (ssl) {
        if (SSL_write(ssl, frame_header, header_idx) <= 0) return -1;
        if (SSL_write(ssl, text, (int)len) <= 0) return -1;
    } else {
        // Gunakan MSG_NOSIGNAL agar server gak crash kalau client tiba-tiba putus (SIGPIPE)
        if (send(sock_client, frame_header, header_idx, MSG_NOSIGNAL) <= 0) return -1;
        if (send(sock_client, text, len, MSG_NOSIGNAL) <= 0) return -1;
    }

    return 0;
}

/* ===================================================================
 * 6. BACKGROUND MAINTENANCE (HEARTBEAT & REAPER)
 * =================================================================== */

void halmos_ws_system_init() {
    // 1. Siapin Buku Alamat (Cuma sekali!)
    ws_registry_init();
    
    // 2. Nyalakan Tukang Pukul Lonceng (Thread Maintenance)
    halmos_ws_start_maintenance();
    
    write_log("[WS] Infrastructure Ready.");
}

void halmos_ws_cleanup_fd(int fd) {
    // Di sini kita cek dulu, apakah FD ini memang WebSocket?
    if (halmos_is_websocket_fd(fd)) {
        // Hapus dari buku alamat
        ws_registry_remove(fd);
        // Reset flag-nya
        halmos_set_websocket_fd(fd, false);
        
        write_log("[WS] Cleanup complete for FD %d", fd);
    }
}

// Tambahkan di halmos_websocket.c
void halmos_ws_system_destroy() {
    // 1. Matikan registry dan free semua memori client
    ws_registry_destroy();
    
    // (Opsional) Jika nanti ada thread maintenance yang butuh dimatikan manual, 
    // taruh logikanya di sini.
    
    write_log("[WS] System resources destroyed.");
}
/*
FUNGSI HELPER
*/
/**
 * Membangun kunci jawaban "Sec-WebSocket-Accept" sesuai RFC 6455.
 */

char* ws_base64_encode(const unsigned char *input, int length){
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *output, *p;
    int i;
    int out_len = 4 * ((length + 2) / 3);

    output = malloc(out_len + 1);
    if (!output) return NULL;

    p = output;
    for (i = 0; i < length - 2; i += 3) {
        *p++ = table[(input[i] >> 2) & 0x3F];
        *p++ = table[((input[i] & 0x3) << 4) | (input[i+1] >> 4)];
        *p++ = table[((input[i+1] & 0xF) << 2) | (input[i+2] >> 6)];
        *p++ = table[input[i+2] & 0x3F];
    }
    if (i < length) {
        *p++ = table[(input[i] >> 2) & 0x3F];
        if (i == (length - 1)) {
            *p++ = table[(input[i] & 0x3) << 4];
            *p++ = '=';
        } else {
            *p++ = table[((input[i] & 0x3) << 4) | (input[i+1] >> 4)];
            *p++ = table[((input[i+1] & 0xF) << 2)];
        }
        *p++ = '=';
    }
    *p = '\0';
    return output;
}

char* ws_create_accept_key(const char *client_key){
    if (!client_key) return NULL;

    char combined[256];
    unsigned char sha1_res[SHA_DIGEST_LENGTH];

    // Gabungkan Key dari Browser + Magic GUID
    snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);

    // SHA1 hashing (Binary)
    SHA1((unsigned char*)combined, strlen(combined), sha1_res);

    // Encode hasil hash ke Base64 (Ini manggil fungsi malloc lu di atas)
    return ws_base64_encode(sha1_res, SHA_DIGEST_LENGTH);
}

/**
 * Base64 encode manual agar tidak ketergantungan OpenSSL BIO yang lambat.
 */

/**
 * Wrapper recv yang mendukung TLS dan Plaintext secara transparan.
 */
ssize_t ws_low_level_recv(int fd, void *buf, size_t len){
    // 1. Cek apakah socket ini punya objek SSL (dari halmos_tls.h)
    SSL *ssl = get_ssl_for_fd(fd);

    if (ssl != NULL) {
        // Jalur HTTPS / WSS
        int n = SSL_read(ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN; // Paksa errno ke EAGAIN biar core Halmos lu paham
            }
        }
        return (ssize_t)n;
    }

    // 2. Jalur HTTP / WS (Plaintext)
    // Gunakan MSG_DONTWAIT karena kita main di arsitektur Non-Blocking Epoll
    return recv(fd, buf, len, MSG_DONTWAIT);
}

/**
 * Mengirim frame PONG sederhana sebagai balasan PING.
 */
void halmos_ws_send_pong(int sock_client) {
    unsigned char pong_frame[2] = {0x8A, 0x00}; // FIN=1, Opcode=0xA (Pong), Len=0
    SSL *ssl = get_ssl_for_fd(sock_client);
    if (ssl) SSL_write(ssl, pong_frame, 2);
    else send(sock_client, pong_frame, 2, MSG_NOSIGNAL);
}

/**
 * Fungsi internal thread yang akan berjalan selamanya di background.
 * Kita buat static karena hanya dipanggil via starter di file ini.
 */
void* halmos_ws_maintenance_run(void *arg) {
    (void)arg;
    write_log("[WS-SYSTEM] Background Maintenance Thread Started.");

    while (1) {
        // Tidur 30 detik (Atur sesuai selera server lu)
        sleep(30);

        // 1. Kirim PING ke semua client di registry
        ws_registry_heartbeat();

        // 2. (Next Step) Panggil Reaper untuk nendang yang AFK
        ws_registry_reaper();

        // 3. Opsional: Intip status registry tiap 30 detik
        // ws_registry_show(); 
    }
    return NULL;
}

/**
 * Fungsi Starter Publik.
 * Inilah yang dipanggil satu kali di main/event_loop.
 */
void halmos_ws_start_maintenance() {
    pthread_t tid;
    if (pthread_create(&tid, NULL, halmos_ws_maintenance_run, NULL) == 0) {
        pthread_detach(tid); // Lepas agar resource otomatis bebas saat thread selesai
    } else {
        write_log_error("[WS-SYSTEM] Failed to start maintenance thread!");
    }
}