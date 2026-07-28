#include "halmos_http2_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http2_parser.h"
#include "halmos_http2_response.h"
#include "halmos_http_multipart.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>

#define HTTP2_MAX_FRAME_SIZE 16384

static ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len);
static ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len);
static void http2_send_settings(int fd, bool is_tls);
static void send_settings_ack(int fd, bool is_tls);
static void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment);
static ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len, int timeout_ms);
static HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id);
/* --- TAMBAHAN DEKLARASI HELPER --- */
static int http2_stream_pump_file_chunk(HTTP2Session *session, HTTP2Stream *stream);
static void http2_flush_active_streams_file(HTTP2Session *session) ;

void http2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
    (void)fd; 
    (void)is_tls;
    unsigned char total_buf[16384 + 9]; 
    if (len > 16384) return; 

    // Header 9 Byte
    total_buf[0] = (len >> 16) & 0xFF;
    total_buf[1] = (len >> 8) & 0xFF;
    total_buf[2] = len & 0xFF;
    total_buf[3] = type;
    total_buf[4] = flags;
    
    uint32_t sid = stream_id & 0x7FFFFFFF;
    total_buf[5] = (sid >> 24) & 0xFF;
    total_buf[6] = (sid >> 16) & 0xFF;
    total_buf[7] = (sid >> 8) & 0xFF;
    total_buf[8] = sid & 0xFF;

    if (len > 0 && payload != NULL) {
        memcpy(total_buf + 9, payload, len);
    }

    // =========================================================================
    // CETAK SEMUA FRAME YANG BENAR-BENAR DITERUSKAN KE WIRE/SOCKET
    // =========================================================================
    fprintf(stderr, "[SOCKET-OUT] Type: 0x%02X | Stream: %u | Length: %u | Flags: 0x%02X", 
            type, stream_id, len, flags);
            
    if (type == 0x01 && len > 0 && payload != NULL) { // HEADERS Frame
        const unsigned char *p = (const unsigned char *)payload;
        fprintf(stderr, " | First Payload Byte: 0x%02X", p[0]);
    }
    fprintf(stderr, "\n");
    // =========================================================================
    ssize_t total_sent = h2_write(fd, is_tls, total_buf, len + 9);
    if (total_sent < (ssize_t)(len + 9)) {
        write_log_error("[H2-SOCKET] Partial write on frame type 0x%02X", type);
    }
}

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    fprintf(stderr, "[H2-IN-HEADERS-START] Processing HEADERS for Stream %u (Length: %u)\n", head->stream_id, head->length);
    
    if (!session || head->stream_id == 0) return;

    HTTP2Stream *st = NULL;
    uint32_t bucket = get_bucket_fibonacci(head->stream_id);

    pthread_mutex_lock(&session->streams_lock);
    
    HTTP2Stream *check = session->streams_hash[bucket];
    while (check != NULL) {
        if (check->stream_id == head->stream_id) {
            st = check;
            break;
        }
        check = check->node_next;
    }

    if (!st) {
        st = calloc(1, sizeof(HTTP2Stream));
        if (!st) {
            pthread_mutex_unlock(&session->streams_lock);
            write_log_error("[H2-ERROR] Malloc failed for new stream ID %u", head->stream_id);
            return;
        }
        st->stream_id = head->stream_id;
        st->http1_compat.is_tls = session->is_tls;

        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        
        strncpy(st->http1_compat.client_ip, "0.0.0.0", sizeof(st->http1_compat.client_ip) - 1);
        st->http1_compat.client_ip[sizeof(st->http1_compat.client_ip) - 1] = '\0';
        
        if (getpeername(session->fd, (struct sockaddr*)&addr, &addr_len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&addr;
                inet_ntop(AF_INET, &s->sin_addr, st->http1_compat.client_ip, sizeof(st->http1_compat.client_ip));
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
                inet_ntop(AF_INET6, &s->sin6_addr, st->http1_compat.client_ip, sizeof(st->http1_compat.client_ip));
            }
        }

        st->node_next = session->streams_hash[bucket];
        session->streams_hash[bucket] = st;
        session->active_stream_count++; 
    }
    pthread_mutex_unlock(&session->streams_lock);

    // =========================================================================
    // STRIP PADDED & PRIORITY HEADERS
    // =========================================================================
    const unsigned char *hpack_payload = payload;
    size_t hpack_len = head->length;

    uint8_t pad_len = 0;
    if (head->flags & 0x08) { // 0x08 = PADDED Flag
        if (hpack_len > 0) {
            pad_len = hpack_payload[0];
            hpack_payload += 1;
            hpack_len -= 1;
        }
    }

    if (head->flags & 0x20) { // 0x20 = PRIORITY Flag
        if (hpack_len >= 5) {
            hpack_payload += 5; 
            hpack_len -= 5;
        }
    }

    if (hpack_len > pad_len) {
        hpack_len -= pad_len; 
    } else {
        hpack_len = 0;
    }

    fprintf(stderr, "[H2-IN-HEADERS] Stream %u | Clean HPACK Len: %zu | Flags: 0x%02X\n", 
            head->stream_id, hpack_len, head->flags);

    // Lempar hpack_payload ke HPACK Parser
    if (http2_parser_parse_header(session, st, hpack_payload, hpack_len) == true) {
        if (config.rate_limit_enabled == true) {
            int limit = (config.max_requests_per_sec > 0) ? config.max_requests_per_sec : 50;
            if (!sec_traffic_is_request_allowed(st->http1_compat.client_ip, limit)) {
                write_log("[H2-SECURITY] Rate limit exceeded for IP: %s. Stream %u rejected.", 
                          st->http1_compat.client_ip, head->stream_id);
                
                unsigned char error_payload[4] = {0x00, 0x00, 0x00, 0x07}; 
                http2_send_frame(session->fd, session->is_tls, 0x03, 0x00, head->stream_id, error_payload, 4);
                return; 
            }
        }

        // 1. JALUR WEBSOCKET UPGRADE VIA HEADERS
        if (st->http1_compat.is_upgrade == true) {
            fprintf(stderr, "[DEBUG-SYNC] Executing WebSocket Upgrade Bridge for Stream %u\n", head->stream_id);
            http2_response_routing_bridge(session, st);
            return;
        }

        // 2. JALUR REQUEST GET / TANPA BODY DATA (END_STREAM = 0x01)
        if (head->flags & 0x01) { 
            fprintf(stderr, "[H2-IN-HEADERS] END_STREAM detected on Stream %u. Crossing to Bridge...\n", head->stream_id);
            
            fprintf(stderr, "[DEBUG-SYNC] Calling routing bridge from headers frame handler...\n");
            http2_response_routing_bridge(session, st);
            fprintf(stderr, "[DEBUG-SYNC] Routing bridge returned control to headers frame handler.\n");

            pthread_mutex_lock(&session->streams_lock);
            st->state = 4; // Closed state
            pthread_mutex_unlock(&session->streams_lock);
            
            fprintf(stderr, "[DEBUG-SYNC] Stream %u marked as CLOSED (state = 4).\n", head->stream_id);
        }
    } else {
        fprintf(stderr, "[H2-IN-HEADERS-ERR] HPACK Parse failed for Stream %u!\n", head->stream_id);
    }

    fprintf(stderr, "[H2-IN-HEADERS-END] Finished processing HEADERS for Stream %u\n", head->stream_id);
}


void http2_handle_data_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session) return;

    HTTP2Stream *st = find_stream(session, head->stream_id);
    if (!st) return;
    
    if (!payload || head->length == 0) return;

    // ===================================================================
    // INTERSEPSI WEBSOCKET HTTP/2 (Membongkar Frame RFC 6455 dari Payload H2)
    // ===================================================================
    if (st->http1_compat.is_upgrade == true) {
        if (head->length < 2) return; // Aman, belum ada lock yang diambil di fungsi ini

        // 1. Bedah Header RFC 6455 yang ada di dalam payload DATA frame HTTP/2
        uint8_t opcode = payload[0] & 0x0F;
        bool masked = (payload[1] & 0x80) != 0;
        uint64_t payload_len = payload[1] & 0x7F;
        size_t header_offset = 2;

        if (payload_len == 126) {
            if (head->length < 4) return;
            uint16_t ext_len;
            memcpy(&ext_len, payload + header_offset, 2);
            payload_len = ntohs(ext_len);
            header_offset += 2;
        } else if (payload_len == 127) {
            if (head->length < 10) return;
            uint64_t ext_len;
            memcpy(&ext_len, payload + header_offset, 8);
            payload_len = be64toh(ext_len);
            header_offset += 8;
        }

        // 2. Ambil Masking Key jika ada
        uint8_t mask[4] = {0};
        if (masked) {
            if (head->length < header_offset + 4) return;
            memcpy(mask, payload + header_offset, 4);
            header_offset += 4;
        }

        // --- MITIGASI EXPLOIT / OVERFLOW ---
        if (header_offset + payload_len > head->length || payload_len == __UINT64_MAX__) {
            return;
        }

        // 3. Alokasikan memori untuk menampung teks JSON yang bersih
        unsigned char *clear_payload = malloc(payload_len + 1);
        if (!clear_payload) return;

        memcpy(clear_payload, payload + header_offset, payload_len);
        clear_payload[payload_len] = '\0';

        // 4. Buka Topeng (Unmasking XOR)
        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                clear_payload[i] ^= mask[i % 4];
            }
        }

        // 5. Eksekusi Berdasarkan Opcode WebSocket (Bebas dari Lock Session)
        if (opcode == 0x01) { // WS_OP_TEXT
            ws_system_on_message(session->fd, head->stream_id, (unsigned char *)clear_payload, payload_len);
        } else if (opcode == 0x08) { // WS_OP_CLOSE
            // Handle close stream jika diperlukan
        }

        free(clear_payload);

        // Kirim WINDOW_UPDATE agar flow-control HTTP/2 berjalan lancar
        http2_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
        http2_send_window_update(session->fd, session->is_tls, 0, head->length);
        return; 
    }

    // ===================================================================
    // --- JALUR DATA HTTP/FASTCGI NORMAL (LOCKING HANYA DI BLOK INI) ---
    // ===================================================================
    pthread_mutex_lock(&session->streams_lock);

    RequestHeader *req = &st->http1_compat;
    size_t new_size = req->body_length + head->length;
    
    // Proteksi tambahan: hindari integer overflow
    if (new_size < req->body_length) {
        pthread_mutex_unlock(&session->streams_lock);
        return;
    }

    unsigned char *temp_body = realloc(req->body_data, new_size + 1);
    if (!temp_body) {
        pthread_mutex_unlock(&session->streams_lock); 
        write_log_error("[H2-ERROR] Realloc failed for Stream ID %d", head->stream_id);
        return; 
    }
    req->body_data = temp_body;

    memcpy((char*)req->body_data + req->body_length, payload, head->length);
    req->body_length = new_size;
    ((char*)req->body_data)[req->body_length] = '\0';

    // Salin flag sebelum melepas lock
    bool is_end_stream = (head->flags & 0x01);

    pthread_mutex_unlock(&session->streams_lock);

    // Kirim window update untuk jalur data HTTP normal
    http2_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
    http2_send_window_update(session->fd, session->is_tls, 0, head->length);

    if (is_end_stream) { 
        pthread_mutex_lock(&session->streams_lock);
        req->content_length = (int)req->body_length; 
        pthread_mutex_unlock(&session->streams_lock);

        // Menyeberang ke FastCGI Backend
        http2_response_routing_bridge(session, st);

        pthread_mutex_lock(&session->streams_lock);
        st->state = 4; // Closed state
        pthread_mutex_unlock(&session->streams_lock);
    }
}

int http2_manager_session(int sock_client, bool is_tls) {
    fprintf(stderr, "\n=======================================================\n");
    fprintf(stderr, "[H2-SESSION-START] New HTTP/2 Session initialized on Sock FD: %d (TLS: %s)\n", 
            sock_client, is_tls ? "YES" : "NO");
    fprintf(stderr, "=======================================================\n");

    HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
    if (!session) {
        fprintf(stderr, "[H2-SESSION-ERR] Malloc failed for HTTP2Session!\n");
        return 0;
    }

    session->fd = sock_client;
    session->is_tls = is_tls;
    session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
    session->dyn_table.max_size = 0; 

    pthread_mutex_init(&session->hpack_lock, NULL);
    pthread_mutex_init(&session->streams_lock, NULL); 

    // 1. Kirim SETTINGS Server awal
    http2_send_settings(sock_client, is_tls);
    
    // 2. Baca Client Connection Preface (24 Bytes)
    char preface[24];
    fprintf(stderr, "[H2-SESSION] Waiting for 24-byte Client Connection Preface...\n");
    ssize_t read_preface = h2_read_exactly(sock_client, is_tls, preface, 24, 5000);
    
    if (read_preface < 24) {
        fprintf(stderr, "[H2-SESSION-ERR] Preface incomplete or timeout! Read: %zd/24 bytes. Aborting.\n", read_preface);
        goto cleanup;
    }
    fprintf(stderr, "[H2-SESSION-OK] Client Preface received successfully.\n");

    // 3. Event Loop Pembacaan Frame HTTP/2
    uint32_t frame_count = 0;

    while (1) {
        unsigned char header_buf[9];
        
        // Gunakan timeout -1 (Blocking sampai client kirim data / disconnect secara sah)
        ssize_t n_header = h2_read_exactly(sock_client, is_tls, header_buf, 9, -1);
        
        if (n_header == 0) {
            fprintf(stderr, "[H2-SESSION-CLOSE] Client closed TCP/TLS connection gracefully (EOF).\n");
            break; 
        } 
        else if (n_header < 0) {
            fprintf(stderr, "[H2-SESSION-ERR] Read error or socket reset on FD %d (errno: %d)\n", sock_client, errno);
            break;
        } 
        else if (n_header < 9) {
            fprintf(stderr, "[H2-SESSION-ERR] Incomplete 9-byte frame header read (Got %zd bytes). Disconnecting.\n", n_header);
            break;
        }

        frame_count++;
        HTTP2FrameHeader head;
        if (!http2_parser_frame_header(header_buf, &head)) {
            fprintf(stderr, "[H2-SESSION-ERR] Failed to parse 9-byte HTTP/2 Frame Header!\n");
            break;
        }

        fprintf(stderr, "[H2-FRAME-IN #%u] Type: 0x%02X | Flags: 0x%02X | Stream: %u | Length: %u\n", 
                frame_count, head.type, head.flags, head.stream_id, head.length);

        size_t max_allowed_payload = (config.max_body_size > 0) ? config.max_body_size : 1048576;
        if (head.length > max_allowed_payload) {
            fprintf(stderr, "[H2-SESSION-ERR] Payload length %u exceeds limit %zu!\n", head.length, max_allowed_payload);
            write_log_error("[H2-ERROR] Payload length %u exceeds config limit %zu", head.length, max_allowed_payload);
            break; 
        }

        unsigned char *payload = NULL;
        if (head.length > 0) {
            payload = malloc(head.length);
            if (!payload) {
                fprintf(stderr, "[H2-SESSION-ERR] Malloc failed for payload buffer (%u bytes)!\n", head.length);
                break;
            }
            
            ssize_t n_payload = h2_read_exactly(sock_client, is_tls, payload, head.length, 5000);
            if (n_payload < (ssize_t)head.length) {
                fprintf(stderr, "[H2-SESSION-ERR] Payload timeout/incomplete! Read %zd of %u bytes.\n", n_payload, head.length);
                free(payload);
                break;
            }
        }

        switch (head.type) {
            case 0x00: 
                fprintf(stderr, "[H2-EXEC] Handling DATA Frame (Stream %u)\n", head.stream_id);
                http2_handle_data_frame(session, &head, payload); 
                break;
            case 0x01: 
                fprintf(stderr, "[H2-EXEC] Handling HEADERS Frame (Stream %u)\n", head.stream_id);
                http2_handle_headers_frame(session, &head, payload); 
                break;
            case 0x04: 
                if (!(head.flags & 0x01)) {
                    fprintf(stderr, "[H2-EXEC] SETTINGS received. Replying with SETTINGS ACK (0x01)...\n");
                    send_settings_ack(sock_client, is_tls); 
                } else {
                    fprintf(stderr, "[H2-EXEC] Received SETTINGS ACK from Client.\n");
                }
                break;
            case 0x07: 
                fprintf(stderr, "[H2-EXEC] Received GOAWAY Frame from Client. Closing Session.\n");
                if (payload) free(payload); 
                goto cleanup;
            
            // TAMBAHKAN PENANGANAN WINDOW_UPDATE (0x08)
            case 0x08: {
                uint32_t window_inc = 0;
                if (head.length >= 4 && payload != NULL) {
                    window_inc = ((uint32_t)(payload[0] & 0x7F) << 24) |
                                 ((uint32_t)payload[1] << 16) |
                                 ((uint32_t)payload[2] << 8)  |
                                 ((uint32_t)payload[3]);
                }
                fprintf(stderr, "[H2-EXEC] Received WINDOW_UPDATE Frame for Stream %u (Increment: %u bytes)\n", 
                        head.stream_id, window_inc);
                // Untuk tahap ini, menerima dan mengakui window_update dari client sudah cukup
                // agar state mesin HTTP/2 cURL dan Halmos tetap sinkron secara formal.
                break;
            }

            default: 
                fprintf(stderr, "[H2-EXEC] Unhandled Frame Type: 0x%02X (Ignored)\n", head.type);
                break;
        }

        if (payload) free(payload);
        http2_flush_active_streams_file(session);
    }

cleanup:
    fprintf(stderr, "[H2-SESSION-CLEANUP] Destroying Session resources on FD %d...\n", sock_client);

    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) { 
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            HTTP2Stream *next_node = curr->node_next; 

            /* --- TAMBAHAN: TUTUP FILE FD DARI STREAM JIKA MASIH TERBUKA --- */
            if (curr->file_fd >= 0) {
                close(curr->file_fd);
                curr->file_fd = -1;
            }

            if (curr->http1_compat.body_data) {
                free(curr->http1_compat.body_data);
                curr->http1_compat.body_data = NULL;
            }
            http2_parser_free_memory(curr);
            free(curr);
            curr = next_node;
        }
        session->streams_hash[i] = NULL;
    }

    if (session->dyn_table.entries) {
        for (uint32_t i = 0; i < session->dyn_table.count; i++) {
            if (session->dyn_table.entries[i].name) free(session->dyn_table.entries[i].name);
            if (session->dyn_table.entries[i].value) free(session->dyn_table.entries[i].value);
        }
        free(session->dyn_table.entries);
    }

    pthread_mutex_destroy(&session->hpack_lock);
    pthread_mutex_destroy(&session->streams_lock);
    free(session);

    fprintf(stderr, "[H2-SESSION-END] Session cleanly closed on FD %d.\n=======================================================\n\n", sock_client);
    return 0;
}

uint32_t get_bucket_fibonacci(uint32_t stream_id) {
    uint32_t hash = stream_id * HTTP2_GOLDEN_RATIO_32;
    return hash >> (32 - HTTP2_HASH_POWER);
}

/* private */

ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len){
    if (is_tls) return ssl_send(fd, buf, len);
    return write(fd, buf, len);
}

ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len){
    if (is_tls) {
        SSL *ssl = ssl_get_for_fd(fd);
        if (!ssl) return -1;
        return (ssize_t)SSL_read(ssl, buf, (int)len);
    }
    return read(fd, buf, len);
}

void http2_send_settings(int fd, bool is_tls) {
    // SETTINGS Frame dengan INITIAL_WINDOW_SIZE (0x0004) dikirim 1 MB (0x00100000)
    unsigned char settings[] = {
        0x00, 0x00, 0x12,       // Payload Length: 18 bytes (3 settings)
        0x04,                   // Frame Type: SETTINGS (0x04)
        0x00,                   // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0

        0x00, 0x01,             // Setting ID: 0x0001 (HEADER_TABLE_SIZE)
        0x00, 0x00, 0x00, 0x00, // Value: 0

        0x00, 0x03,             // Setting ID: 0x0003 (MAX_CONCURRENT_STREAMS)
        0x00, 0x00, 0x00, 0x64, // Value: 100

        0x00, 0x04,             // Setting ID: 0x0004 (INITIAL_WINDOW_SIZE)
        0x00, 0x10, 0x00, 0x00  // Value: 1,048,576 bytes (1 MB Window Size)
    };
    
    fprintf(stderr, "[H2-SESSION] Sending Initial SETTINGS Frame (27 bytes)...\n");
    h2_write(fd, is_tls, settings, 27);
}

void send_settings_ack(int fd, bool is_tls){
    unsigned char ack[9] = {0,0,0, 4, 1, 0,0,0,0}; 
    h2_write(fd, is_tls, ack, 9);
}

void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment) {
    unsigned char payload[4];
    payload[0] = (increment >> 24) & 0x7F;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >> 8) & 0xFF;
    payload[3] = increment & 0xFF;
    http2_send_frame(fd, is_tls, 0x08, 0x00, stream_id, payload, 4);
}

ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len, int timeout_ms) {
    size_t total_read = 0;
    char *ptr = (char *)buf;

    while (total_read < len) {
        if (timeout_ms != -1 && timeout_ms <= 0) return -1;

        ssize_t n = h2_read(fd, is_tls, ptr + total_read, len - total_read);
        if (n > 0) {
            total_read += n;
        } else if (n == 0) {
            return (ssize_t)total_read; 
        } else {
            bool retry_it = false;
            if (is_tls) {
                SSL *ssl = ssl_get_for_fd(fd);
                int err_code = SSL_get_error(ssl, (int)n);
                if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) retry_it = true;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) retry_it = true;
            }

            if (retry_it) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                int interval = 50; 
                int poll_timeout = (timeout_ms == -1) ? -1 : interval;
                
                int res = poll(&pfd, 1, poll_timeout);
                if (res > 0) {
                    if (timeout_ms != -1) timeout_ms -= interval;
                    continue;
                } else if (res == 0 && timeout_ms != -1) {
                    timeout_ms -= interval;
                    continue;
                }
                break; 
            }
            break;
        }
    }
    return (ssize_t)total_read;
}

HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id) {
    if (!session || id == 0) return NULL;
    uint32_t bucket = get_bucket_fibonacci(id);
    
    pthread_mutex_lock(&session->streams_lock);
    HTTP2Stream *curr = session->streams_hash[bucket];
    while (curr != NULL) {
        if (curr->stream_id == id) {
            pthread_mutex_unlock(&session->streams_lock); 
            return curr;
        }
        curr = curr->node_next;
    }
    pthread_mutex_unlock(&session->streams_lock); 
    return NULL;
}

/**
 * Memompa 1 Chunk File (Maksimal 16 KB) ke Socket TLS.
 * Return:
 *   0  : Pengiriman selesai penuh (END_STREAM terkirim & file_fd ditutup)
 *   1  : Masih ada sisa chunk (harus dipanggil lagi di iterasi berikutnya/EPOLLOUT)
 *  -1  : Socket Error / System Error (koneksi putus)
 */
/**
 * Memompa 1 Chunk File (Maksimal 16 KB) ke Socket.
 * Return:
 *   0  : Pengiriman selesai penuh (END_STREAM terkirim & file_fd ditutup)
 *   1  : Masih ada sisa chunk (harus dipanggil lagi di iterasi berikutnya)
 *  -1  : Socket Error / System Error (koneksi putus)
 */
int http2_stream_pump_file_chunk(HTTP2Session *session, HTTP2Stream *stream) {
    if (!session || !stream || !stream->is_sending_file || stream->file_fd < 0) {
        return 0; // Tidak ada file yang perlu dipompa
    }

    // 1. Hitung sisa byte file yang belum terkirim
    if (stream->file_offset >= stream->file_size) {
        close(stream->file_fd);
        stream->file_fd = -1;
        stream->is_sending_file = false;
        return 0;
    }

    off_t bytes_remaining = stream->file_size - stream->file_offset;
    
    // Batasi payload chunk maksimal 16 KB per frame
    uint32_t payload_len = (bytes_remaining > (off_t)HTTP2_MAX_FRAME_SIZE) 
                           ? HTTP2_MAX_FRAME_SIZE 
                           : (uint32_t)bytes_remaining;

    // Tentukan flag: Jika ini chunk terakhir, pasang END_STREAM (0x01)
    uint8_t flags = 0;
    if (stream->file_offset + (off_t)payload_len >= stream->file_size) {
        flags |= 0x01; // HTTP2_FLAG_END_STREAM
    }

    // 2. Alokasikan buffer sementara untuk Frame (9 Byte Header + Payload)
    uint8_t frame_buf[9 + HTTP2_MAX_FRAME_SIZE];

    // Susun 9-byte Frame Header HTTP/2 (DATA Frame = 0x00)
    frame_buf[0] = (payload_len >> 16) & 0xFF;
    frame_buf[1] = (payload_len >> 8)  & 0xFF;
    frame_buf[2] = payload_len & 0xFF;
    frame_buf[3] = 0x00; // Type DATA
    frame_buf[4] = flags;
    
    uint32_t sid = stream->stream_id & 0x7FFFFFFF;
    frame_buf[5] = (sid >> 24) & 0xFF;
    frame_buf[6] = (sid >> 16) & 0xFF;
    frame_buf[7] = (sid >> 8)  & 0xFF;
    frame_buf[8] = sid & 0xFF;

    // 3. Baca data dari file_fd ke buffer frame (setelah 9 byte header)
    ssize_t n_read = pread(stream->file_fd, frame_buf + 9, payload_len, stream->file_offset);
    if (n_read <= 0) {
        write_log_error("[H2-PUMP] Failed to read from file_fd %d", stream->file_fd);
        close(stream->file_fd);
        stream->file_fd = -1;
        stream->is_sending_file = false;
        return -1;
    }

    // 4. Kirim frame utuh via h2_write (Mencakup Socket TLS maupun Non-TLS)
    size_t total_frame_size = 9 + (size_t)n_read;
    ssize_t sent = h2_write(session->fd, session->is_tls, frame_buf, total_frame_size);
    if (sent < (ssize_t)total_frame_size) {
        write_log_error("[H2-PUMP] Write error/partial write on Stream %u", stream->stream_id);
        close(stream->file_fd);
        stream->file_fd = -1;
        stream->is_sending_file = false;
        return -1;
    }

    // 5. Update offset
    stream->file_offset += n_read;

    // 6. Cek apakah transmisi selesai
    if (stream->file_offset >= stream->file_size) {
        close(stream->file_fd);
        stream->file_fd = -1;
        stream->is_sending_file = false;
        return 0; // Selesai
    }

    return 1; // Masih ada chunk tersisa
}

void http2_flush_active_streams_file(HTTP2Session *session) {
    if (!session) return;

    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            HTTP2Stream *next_node = curr->node_next; // Amankan pointer sebelum lepas lock

            if (curr->is_sending_file && curr->file_fd >= 0) {
                pthread_mutex_unlock(&session->streams_lock);
                
                http2_stream_pump_file_chunk(session, curr);
                
                pthread_mutex_lock(&session->streams_lock);
            }
            curr = next_node;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);
}