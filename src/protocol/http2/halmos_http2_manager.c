#include "halmos_http2_manager.h"
#include "halmos_http2_parser.h"
#include "halmos_http2_response.h"
#include "halmos_http_multipart.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/*void debug_hexdump(const char *label, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    fprintf(stdout, "[DEBUG-HEX] %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stdout, "%02X ", p[i]);
    }
    fprintf(stdout, "\n");
}*/

static ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len);

static ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len);

static void http2_send_settings(int fd, bool is_tls);

static void send_settings_ack(int fd, bool is_tls);

static void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment);

/**
 * Memastikan kita membaca tepat 'len' byte.
 * Jika kurang, dia akan mengulang sampai lengkap atau error.
 */
static ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len);

static HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id);

/* Public function */
/**
 * Fungsi tunggal untuk mengirim segala jenis HTTP/2 Frame.
 * Membungkus kerumitan bit-shifting Stream ID dan Length.
 */

void http2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
    (void)fd; 
    (void)is_tls;
    // Kita buat buffer gabungan (9 byte header + payload)
    // Gunakan array statis besar atau malloc untuk payload besar
    unsigned char total_buf[16384 + 9]; 
    if (len > 16384) return; // Batasi sesuai max frame size default

    // 1. Isi Header di awal buffer
    total_buf[0] = (len >> 16) & 0xFF;
    total_buf[1] = (len >> 8) & 0xFF;
    total_buf[2] = len & 0xFF;
    total_buf[3] = type;
    total_buf[4] = flags;
    total_buf[5] = (stream_id >> 24) & 0x7F; 
    total_buf[6] = (stream_id >> 16) & 0xFF;
    total_buf[7] = (stream_id >> 8) & 0xFF;
    total_buf[8] = stream_id & 0xFF;

    // 2. Copy Payload setelah header
    if (len > 0 && payload != NULL) {
        memcpy(total_buf + 9, payload, len);
    }

    // --- TRACING HEX DUMP ---
    /*fprintf(stderr, "[H2-SEND-TRACE] Type: 0x%02X, Flags: 0x%02X, Stream: %u, Total Len: %u\n", type, flags, stream_id, len + 9);
    fprintf(stderr, "[H2-HEX-DUMP] ");
    for (uint32_t i = 0; i < (len + 9 > 32 ? 32 : len + 9); i++) { // Dump 32 byte pertama saja biar nggak menuhi log
        fprintf(stderr, "%02X ", total_buf[i]);
    }
    fprintf(stderr, "...\n");
    */

    // 3. KIRIM SEKALIGUS (ATOMIC)
    
    ssize_t total_sent = h2_write(fd, is_tls, total_buf, len + 9);
    if (total_sent < (ssize_t)(len + 9)) {
        //fprintf(stderr, "[H2 ERROR] Partial write: %zd/%u\n", total_sent, len + 9);
    }
}

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session || head->stream_id == 0) return;

    int idx = head->stream_id % 100;
    HTTP2Stream *st = &session->streams[idx];

    // Jika slot ini sudah pernah dipakai Stream ID lain, bersihkan!
    if (st->stream_id != 0 && st->stream_id != head->stream_id) {
        http2_parser_free_memory(st);
        memset(st, 0, sizeof(HTTP2Stream));
    }

    // Set identitas stream baru
    st->stream_id = head->stream_id;
    st->http1_compat.is_tls = session->is_tls;

    // Lanjut decode HPACK
    if (http2_hpack_decode(session, st, payload, head->length)) {
        // Jika HEADERS frame punya flag END_STREAM (0x01), langsung proses (misal GET)
        if (head->flags & 0x01) {
            http2_response_routing_bridge(session, st);
        }
    }
}

void http2_handle_data_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    HTTP2Stream *st = find_stream(session, head->stream_id);
    if (!st || !payload) return;

    RequestHeader *req = &st->http1_compat;

    // 1. DYNAMIC REALLOC
    size_t new_size = req->body_length + head->length;
    unsigned char *temp_body = realloc(req->body_data, new_size + 1);
    
    if (!temp_body) {
        write_log_error("[H2-ERROR] Realloc failed for Stream ID %d", head->stream_id);
        return; 
    }
    req->body_data = temp_body;

    // 2. COPY DATA
    memcpy((char*)req->body_data + req->body_length, payload, head->length);
    req->body_length = new_size;
    ((char*)req->body_data)[req->body_length] = '\0';

    // 3. LOGGING
    //fprintf(stderr, "[H2-DATA] Stream %d received %u bytes. Total: %zu\n", 
    //        head->stream_id, head->length, req->body_length);

    // --- UPDATE DI SINI (KELUAR DARI IF) ---
    // Kirim WINDOW_UPDATE SETIAP KALI data diterima (per frame)
    // agar browser tahu Halmos masih punya ruang di buffer.
    http2_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
    http2_send_window_update(session->fd, session->is_tls, 0, head->length);
    // ---------------------------------------

    // 4. TRIGGER BRIDGE
    if (head->flags & 0x01) { // END_STREAM diterima
        req->content_length = (int)req->body_length; 

        // Panggil bridge untuk kirim ke Backend (PHP, Py, Rust)
        http2_response_routing_bridge(session, st);

        // Setelah bridge selesai, kita harus membersihkan buffer agar tidak 
        // dianggap request POST baru jika ada sisa fragment di buffer socket.
        req->body_length = 0; 
        if(req->body_data) {
            free(req->body_data);
            req->body_data = NULL;
        }
    }
}

int http2_manager_session(int sock_client, bool is_tls) {
    HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
    if (!session) return 0;

    session->fd = sock_client;
    session->is_tls = is_tls;

    // Init HPACK
    session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
    session->dyn_table.max_size = 0; 

    // Init Locks
    pthread_mutex_init(&session->hpack_lock, NULL);
    pthread_mutex_init(&session->streams_lock, NULL); // Jangan lupa ini

    // Kirim Settings & Baca Preface
    http2_send_settings(sock_client, is_tls);
    char preface[24];
    if (h2_read_exactly(sock_client, is_tls, preface, 24) < 24) goto cleanup;

    while (1) {
        unsigned char header_buf[9];
        // Baca Frame Header (9 bytes)
        if (h2_read_exactly(sock_client, is_tls, header_buf, 9) < 9) break;

        HTTP2FrameHeader head;
        if (!http2_parse_frame_header(header_buf, &head)) break;

        // Proteksi payload yang terlalu besar (misal > 1MB)
        if (head.length > 1048576) break; 

        unsigned char *payload = NULL;
        if (head.length > 0) {
            payload = malloc(head.length);
            if (!payload) break;
            if (h2_read_exactly(sock_client, is_tls, payload, head.length) < (ssize_t)head.length) {
                free(payload);
                break;
            }
        }

        switch (head.type) {
            case 0x00: http2_handle_data_frame(session, &head, payload); break;
            case 0x01: http2_handle_headers_frame(session, &head, payload); break;
            case 0x04: if (!(head.flags & 0x01)) send_settings_ack(sock_client, is_tls); break;
            case 0x07: if (payload) free(payload); goto cleanup;
            default: /* Frame lain abaikan dulu */ break;
        }
        if (payload) free(payload);
    }

cleanup:
    pthread_mutex_destroy(&session->hpack_lock);
    pthread_mutex_destroy(&session->streams_lock);

    // 1. Bersihkan sisa data di setiap Stream (Body & HPACK strings)
    for (int i = 0; i < 100; i++) { 
        if (session->streams[i].http1_compat.body_data) {
            free(session->streams[i].http1_compat.body_data);
            session->streams[i].http1_compat.body_data = NULL;
        }
        http2_parser_free_memory(&session->streams[i]);
    }

    // 2. Bersihkan isi Dynamic Table (String hasil strdup)
    if (session->dyn_table.entries) {
        for (uint32_t i = 0; i < session->dyn_table.count; i++) {
            if (session->dyn_table.entries[i].name) {
                free(session->dyn_table.entries[i].name);
            }
            if (session->dyn_table.entries[i].value) {
                free(session->dyn_table.entries[i].value);
            }
        }
        // Baru kemudian free array-nya
        free(session->dyn_table.entries);
    }

    free(session);
    return 0;
}

/* Impementasi private fungtion - Helper */
ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len){
    //debug_hexdump("WRITE", buf, len);
    if (is_tls) return ssl_send(fd, buf, len);
    return write(fd, buf, len);
}

ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len){
    if (is_tls) {
        // Ambil objek SSL yang sudah kamu simpan di mapping
        SSL *ssl = ssl_get_for_fd(fd);
        if (!ssl) return -1;
        // Langsung panggil fungsi asli OpenSSL
        return (ssize_t)SSL_read(ssl, buf, (int)len);
    }
    return read(fd, buf, len);
}

void http2_send_settings(int fd, bool is_tls) {
    // 9 byte Frame Header + 6 byte Payload (Total 15 byte)
    unsigned char settings[] = {
        0x00, 0x00, 0x06,       // Length: 6 byte
        0x04,                   // Type: SETTINGS (0x04)
        0x00,                   // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        
        // Payload: SETTINGS_HEADER_TABLE_SIZE (ID 1) = 0
        0x00, 0x01,             // ID: 1
        0x00, 0x00, 0x00, 0x00  // Value: 0
    };
    h2_write(fd, is_tls, settings, 15);
    //fprintf(stdout, "[H2] Initial SETTINGS (Table Size 0) sent to FD %d\n", fd);
}

void send_settings_ack(int fd, bool is_tls){
    unsigned char ack[9] = {0,0,0, 4, 1, 0,0,0,0}; // Length 0, Type 4 (Settings), Flag 1 (ACK)
    h2_write(fd, is_tls, ack, 9);
    //fprintf(stdout, "[H2] Sent SETTINGS ACK to FD %d\n", fd);
}

void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment) {
    unsigned char payload[4];
    payload[0] = (increment >> 24) & 0x7F;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >> 8) & 0xFF;
    payload[3] = increment & 0xFF;

    // Type 0x08 adalah WINDOW_UPDATE
    http2_send_frame(fd, is_tls, 0x08, 0x00, stream_id, payload, 4);
}

ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len) {
    size_t total_read = 0;
    char *ptr = (char *)buf;

    while (total_read < len) {
        ssize_t n = h2_read(fd, is_tls, ptr + total_read, len - total_read);
        
        if (n > 0) {
            total_read += n;
        } else if (n == 0) {
            return (ssize_t)total_read; // Koneksi putus
        } else {
            // Jika menggunakan OpenSSL, kamu harus cek SSL_ERROR_WANT_READ
            // Tapi untuk sekarang, kita asumsikan ini block/retry
            usleep(1000); // Kasih nafas 1ms buat nunggu buffer terisi
            continue; 
        }
    }
    /*if (total_read > 0) {
        debug_hexdump("READ ", buf, total_read); // Lihat apa yang dikirim client
    }*/
    return (ssize_t)total_read;
}

HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id) {
    int idx = id % 100; // Langsung tuju slotnya, jangan loop!
    if (session->streams[idx].stream_id == id) {
        return &session->streams[idx];
    }
    return NULL;
}