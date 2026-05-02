#include "halmos_http2_manager.h"
#include "halmos_http2_parser.h"
#include "halmos_http2_response.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void debug_hexdump(const char *label, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    fprintf(stdout, "[DEBUG-HEX] %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stdout, "%02X ", p[i]);
    }
    fprintf(stdout, "\n");
}

static ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len) {
    debug_hexdump("WRITE", buf, len);
    if (is_tls) return ssl_send(fd, buf, len);
    return write(fd, buf, len);
}

static ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len) {
    if (is_tls) {
        // Ambil objek SSL yang sudah kamu simpan di mapping
        SSL *ssl = ssl_get_for_fd(fd);
        if (!ssl) return -1;
        // Langsung panggil fungsi asli OpenSSL
        return (ssize_t)SSL_read(ssl, buf, (int)len);
    }
    return read(fd, buf, len);
}

static void send_settings_ack(int fd, bool is_tls) {
    unsigned char ack[9] = {0,0,0, 4, 1, 0,0,0,0}; // Length 0, Type 4 (Settings), Flag 1 (ACK)
    h2_write(fd, is_tls, ack, 9);
    fprintf(stdout, "[H2] Sent SETTINGS ACK to FD %d\n", fd);
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
    fprintf(stdout, "[H2] Initial SETTINGS (Table Size 0) sent to FD %d\n", fd);
}

/**
 * Memastikan kita membaca tepat 'len' byte.
 * Jika kurang, dia akan mengulang sampai lengkap atau error.
 */
static ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len) {
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
    if (total_read > 0) {
        debug_hexdump("READ ", buf, total_read); // Lihat apa yang dikirim client
    }
    return (ssize_t)total_read;
}

/**
 * Fungsi tunggal untuk mengirim segala jenis HTTP/2 Frame.
 * Membungkus kerumitan bit-shifting Stream ID dan Length.
 */

void h2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
    unsigned char frame[9];

    // 1. Payload Length (24-bit)
    frame[0] = (len >> 16) & 0xFF;
    frame[1] = (len >> 8) & 0xFF;
    frame[2] = len & 0xFF;

    // 2. Type & Flags
    frame[3] = type;
    frame[4] = flags;

    // 3. Stream ID (31-bit, bit ke-32 reserved/0)
    frame[5] = (stream_id >> 24) & 0x7F; 
    frame[6] = (stream_id >> 16) & 0xFF;
    frame[7] = (stream_id >> 8) & 0xFF;
    frame[8] = stream_id & 0xFF;

    // --- PERBAIKAN STRATEGI PENGIRIMAN ---
    
    // Jika payload kecil (misal di bawah 1400 byte), 
    // sebenarnya lebih bagus digabung pakai buffer lokal kecil agar jadi 1 paket TCP.
    // Tapi untuk general use, kita pastikan header terkirim dulu.
    
    if (h2_write(fd, is_tls, frame, 9) < 9) {
        // Log error jika kirim header saja gagal
        // fprintf(stderr, "[H2 ERROR] Failed to send frame header to FD %d\n", fd);
        return;
    }

    // 4. Kirim Payload jika ada
    if (len > 0 && payload != NULL) {
        // h2_write harus dipastikan bisa menangani partial write (looping send)
        if (h2_write(fd, is_tls, payload, len) < (ssize_t)len) {
            // Log error jika payload gagal terkirim utuh
            // fprintf(stderr, "[H2 ERROR] Failed to send frame payload to FD %d\n", fd);
        }
    }
}

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    HTTP2Stream *stream = calloc(1, sizeof(HTTP2Stream));
    if (!stream) return;

    stream->stream_id = head->stream_id;
    stream->http1_compat.is_tls = session->is_tls;

    // 1. Jalankan Decode
    if (http2_hpack_decode(session, stream, payload, head->length)) {
        // 2. Cek apakah END_HEADERS flag aktif
        if (head->flags & 0x04) {
            
            // 3. SAFETY CHECK: Jangan biarkan printf atau routing memproses NULL
            if (stream->http1_compat.method[0] == '\0' || stream->http1_compat.uri[0] == '\0') {
                fprintf(stderr, "[H2 ERROR] Stream %u: Invalid Headers (NULL Method/URI)\n", stream->stream_id);
            } else {
                fprintf(stdout, "[H2] Stream %u: %s %s\n", 
                        stream->stream_id, stream->http1_compat.method, stream->http1_compat.uri);

                // 4. Hanya panggil bridge jika data VALID
                http2_response_routing_bridge(session, stream);
            }
        }
    } else {
        fprintf(stderr, "[H2 ERROR] HPACK Decode failed for stream %u\n", head->stream_id);
    }

    // 5. Cleanup
    http2_parser_free_memory(stream);
    free(stream);
}

int http2_manager_session(int sock_client, bool is_tls) {
    fprintf(stdout, "[H2] --- New Session Started (FD: %d) ---\n", sock_client);

    HTTP2Session session;
    memset(&session, 0, sizeof(HTTP2Session));
    session.fd = sock_client;
    session.is_tls = is_tls;

    // Alokasi tabel dinamis
    session.dyn_table.entries = calloc(128, sizeof(HPACKEntry));
    if (!session.dyn_table.entries) return 0;

    // Paksa Table Size 0 di awal untuk stabilitas
    session.dyn_table.max_size = 0; 

    if (pthread_mutex_init(&session.hpack_lock, NULL) != 0) {
        free(session.dyn_table.entries);
        return 0;
    }

    http2_send_settings(sock_client, is_tls);

    char preface[24];
    if (h2_read_exactly(sock_client, is_tls, preface, 24) < 24) goto cleanup;

    while (1) {
        unsigned char header_buf[9];
        if (h2_read_exactly(sock_client, is_tls, header_buf, 9) < 9) break;

        HTTP2FrameHeader head;
        if (!http2_parse_frame_header(header_buf, &head)) break;

        unsigned char *payload = NULL;
        if (head.length > 0) {
            if (head.length > 1048576) break; // Limit 1MB payload safety
            payload = malloc(head.length);
            if (!payload) break;
            if (h2_read_exactly(sock_client, is_tls, payload, head.length) < (ssize_t)head.length) {
                free(payload);
                break;
            }
        }

        switch (head.type) {
            case HTTP2_FRAME_SETTINGS:
                if (!(head.flags & 0x01)) send_settings_ack(sock_client, is_tls);
                break;
            case HTTP2_FRAME_HEADERS:
                // Tambahkan log untuk memastikan frame HEADERS masuk
                fprintf(stdout, "[H2] Received HEADERS frame (Stream %u, Len %u)\n", head.stream_id, head.length);
                
                // Coba decode
                http2_handle_headers_frame(&session, &head, payload);
                
                // TEST PANCINGAN: Jika setelah di-handle stream masih diam, 
                // kita paksa kirim 404 sederhana agar Curl tidak menggantung.
                // (Hanya untuk debug, nanti hapus lagi)
                // http2_response_send_header(&session, stream, 404);
                break;
            case HTTP2_FRAME_GOAWAY:
                if (payload) free(payload);
                goto cleanup;
        }
        if (payload) free(payload);
    }

cleanup:
    pthread_mutex_destroy(&session.hpack_lock);
    if (session.dyn_table.entries) {
        // Bebaskan sisa-sisa strdup di tabel dinamis
        for (uint32_t i = 0; i < session.dyn_table.count; i++) {
            if (session.dyn_table.entries[i].name) free(session.dyn_table.entries[i].name);
            if (session.dyn_table.entries[i].value) free(session.dyn_table.entries[i].value);
        }
        free(session.dyn_table.entries);
    }
    return 0;
}



