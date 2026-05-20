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

static ssize_t h2_write(int fd, bool is_tls, const void *buf, size_t len);
static ssize_t h2_read(int fd, bool is_tls, void *buf, size_t len);
static void http2_send_settings(int fd, bool is_tls);
static void send_settings_ack(int fd, bool is_tls);
static void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment);
static ssize_t h2_read_exactly(int fd, bool is_tls, void *buf, size_t len, int timeout_ms);
static HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id);

void http2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
    (void)fd; 
    (void)is_tls;
    unsigned char total_buf[16384 + 9]; 
    if (len > 16384) return; 

    total_buf[0] = (len >> 16) & 0xFF;
    total_buf[1] = (len >> 8) & 0xFF;
    total_buf[2] = len & 0xFF;
    total_buf[3] = type;
    total_buf[4] = flags;
    total_buf[5] = (stream_id >> 24) & 0x7F; 
    total_buf[6] = (stream_id >> 16) & 0xFF;
    total_buf[7] = (stream_id >> 8) & 0xFF;
    total_buf[8] = stream_id & 0xFF;

    if (len > 0 && payload != NULL) {
        memcpy(total_buf + 9, payload, len);
    }
    
    ssize_t total_sent = h2_write(fd, is_tls, total_buf, len + 9);
    if (total_sent < (ssize_t)(len + 9)) {
        // Handle partial write if necessary
    }
}

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
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
        
        // Perbaikan: Gunakan strncpy untuk keamanan buffer
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

    if (http2_parser_parse_header(session, st, payload, head->length) == true) {
        if (config.rate_limit_enabled == true) {
            int limit = (config.max_requests_per_sec > 0) ? config.max_requests_per_sec : 50;
            if (!sec_traffic_is_request_allowed(st->http1_compat.client_ip, limit)) {
                write_log("[H2-SECURITY] Rate limit exceeded for IP: %s. Stream %u rejected.", 
                          st->http1_compat.client_ip, head->stream_id);
                
                unsigned char error_payload[4] = {0x00, 0x00, 0x00, 0x07}; 
                http2_send_frame(session->fd, session->is_tls, 0x03, 0x00, head->stream_id, error_payload, 4);
                
                // ===================================================================
                // PERBAIKAN FATAL MEMORY LEAK:
                // Sebelum keluar fungsi akibat rate limit, payload HARUS dibebaskan 
                // karena siklus free() di loop utama http2_manager_session akan terlewat!
                // ===================================================================
                if (payload) {
                    free((void *)payload);
                }
                return; 
            }
        }

        // 1. JALUR WEBSOCKET UPGRADE VIA HEADERS
        if (st->http1_compat.is_upgrade == true) {
            http2_response_routing_bridge(session, st);
            return;
        }

        // 2. JALUR REQUEST NORMAL
        if (head->flags & 0x01) { 
            http2_response_routing_bridge(session, st);
        }
    } /*else {
        fprintf(stdout, "[H2-ERROR] HPACK decode failed for stream %u\n", head->stream_id);
        fflush(stdout);
    }*/
}

void http2_handle_data_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    //fprintf(stderr, "[H2-DEBUG-DATA] === MASUK DATA FRAME === Stream ID: %u, Length: %u, Flags: 0x%02X\n", 
    //        head->stream_id, head->length, head->flags);

    if (!session) return;

    HTTP2Stream *st = find_stream(session, head->stream_id);
    if (!st) {
        //fprintf(stderr, "[H2-DEBUG-DATA] ERR: Stream ID %u tidak ditemukan di session\n", head->stream_id);
        return;
    }
    if (!payload || head->length == 0) {
        //fprintf(stderr, "[H2-DEBUG-DATA] WARN: Payload kosong pada Stream ID %u\n", head->stream_id);
        return;
    }

    // ===================================================================
    // PENGAMNAN STATE: LOCK MUTEX SEBELUM MEMBACA / MEMODIFIKASI STREAM
    // ===================================================================
    pthread_mutex_lock(&session->streams_lock);

    // ===================================================================
    // INTERSEPSI WEBSOCKET HTTP/2 (Membongkar Frame RFC 6455 dari Payload H2)
    // ===================================================================
    if (st->http1_compat.is_upgrade == true) {
        if (head->length < 2) {
            pthread_mutex_unlock(&session->streams_lock);
            return;
        }

        // 1. Bedah Header RFC 6455 yang ada di dalam payload DATA frame HTTP/2
        uint8_t opcode = payload[0] & 0x0F;
        bool masked = (payload[1] & 0x80) != 0;
        uint64_t payload_len = payload[1] & 0x7F;
        size_t header_offset = 2;

        if (payload_len == 126) {
            if (head->length < 4) {
                pthread_mutex_unlock(&session->streams_lock);
                return;
            }
            uint16_t ext_len;
            memcpy(&ext_len, payload + header_offset, 2);
            payload_len = ntohs(ext_len);
            header_offset += 2;
        } else if (payload_len == 127) {
            if (head->length < 10) {
                pthread_mutex_unlock(&session->streams_lock);
                return;
            }
            uint64_t ext_len;
            memcpy(&ext_len, payload + header_offset, 8);
            payload_len = be64toh(ext_len);
            header_offset += 8;
        }

        // 2. Ambil Masking Key jika ada (Client pasti nge-mask)
        uint8_t mask[4] = {0};
        if (masked) {
            if (head->length < header_offset + 4) {
                pthread_mutex_unlock(&session->streams_lock);
                return;
            }
            memcpy(mask, payload + header_offset, 4);
            header_offset += 4;
        }

        // --- MITIGASI EXPLOIT / OVERFLOW ---
        // Pastikan ukuran frame biner masuk akal dan tidak memicu overflow (payload_len + 1)
        if (header_offset + payload_len > head->length || payload_len == __UINT64_MAX__) {
            pthread_mutex_unlock(&session->streams_lock);
            return;
        }

        // 3. Alokasikan memori untuk menampung teks JSON yang sudah bersih
        unsigned char *clear_payload = malloc(payload_len + 1);
        if (!clear_payload) {
            pthread_mutex_unlock(&session->streams_lock);
            return;
        }

        memcpy(clear_payload, payload + header_offset, payload_len);
        clear_payload[payload_len] = '\0';

        // 4. Buka Topeng (Unmasking XOR)
        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                clear_payload[i] ^= mask[i % 4];
            }
        }

        // Buka lock sebelum memanggil sistem eksternal/callback agar tidak memicu deadlock
        pthread_mutex_unlock(&session->streams_lock);

        // 5. Eksekusi Berdasarkan Opcode WebSocket
        if (opcode == 0x01) { // WS_OP_TEXT
            ws_system_on_message(session->fd, clear_payload, payload_len);
        } else if (opcode == 0x08) { // WS_OP_CLOSE
            //fprintf(stderr, "[H2-WS] Browser me-request Close Stream %u\n", head->stream_id);
        }

        free(clear_payload);

        // Kirim WINDOW_UPDATE agar flow-control HTTP/2 berjalan lancar
        http2_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
        http2_send_window_update(session->fd, session->is_tls, 0, head->length);
        return; 
    }

    // ===================================================================
    // --- JALUR DATA HTTP/FASTCGI NORMAL (SUDAH TERPROTEKSI LOCK) ---
    // ===================================================================
    RequestHeader *req = &st->http1_compat;
    //fprintf(stderr, "[H2-DEBUG-DATA] BEFORE REALLOC -> Stream ID: %u, Current Body Length: %zu\n", 
    //        head->stream_id, req->body_length);

    // Proteksi tambahan: hindari integer overflow pada akumulasi ukuran body
    size_t new_size = req->body_length + head->length;
    if (new_size < req->body_length) {
        pthread_mutex_unlock(&session->streams_lock);
        //fprintf(stderr, "[H2-DEBUG-DATA] FATAL ERR: Integer Overflow detected on body size calculation\n");
        return;
    }

    unsigned char *temp_body = realloc(req->body_data, new_size + 1);
    if (!temp_body) {
        pthread_mutex_unlock(&session->streams_lock); 
        //fprintf(stderr, "[H2-DEBUG-DATA] FATAL ERR: Realloc GAGAL untuk Stream ID %u ke ukuran %zu\n", 
        //        head->stream_id, new_size + 1);
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
        //fprintf(stderr, "[H2-DEBUG-DATA] !!! END_STREAM DETECTED !!! Total Final Length: %zu\n", req->body_length);
        
        pthread_mutex_lock(&session->streams_lock);
        req->content_length = (int)req->body_length; 
        pthread_mutex_unlock(&session->streams_lock);

        //fprintf(stderr, "[H2-DEBUG-DATA] CALLING BRIDGE -> Menyeberang ke FastCGI Backend untuk Stream ID %u...\n", head->stream_id);
        http2_response_routing_bridge(session, st);
        //fprintf(stderr, "[H2-DEBUG-DATA] BACK FROM BRIDGE -> Stream ID %u aman dilempar ke backend.\n", head->stream_id);
    }
    
    //fprintf(stderr, "[H2-DEBUG-DATA] === SELESAI FRAME === Stream ID: %u\n\n", head->stream_id);
}

int http2_manager_session(int sock_client, bool is_tls) {
    HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
    if (!session) return 0;

    session->fd = sock_client;
    session->is_tls = is_tls;
    session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
    session->dyn_table.max_size = 0; 

    pthread_mutex_init(&session->hpack_lock, NULL);
    pthread_mutex_init(&session->streams_lock, NULL); 

    http2_send_settings(sock_client, is_tls);
    
    char preface[24];
    ssize_t read_preface = h2_read_exactly(sock_client, is_tls, preface, 24, 5000);
    if (read_preface < 24) goto cleanup;

    while (1) {
        unsigned char header_buf[9];
        //if (h2_read_exactly(sock_client, is_tls, header_buf, 9, -1) < 9) break;
        // --- PERBAIKAN DI SINI: Ganti -1 menjadi 5000 (5 detik Keep-Alive) ---
        ssize_t n_header = h2_read_exactly(sock_client, is_tls, header_buf, 9, 5000);
        if (n_header < 9) {
            // Jika n_header == 0 (Client menutup koneksi secara normal setelah selesai)
            // Atau jika n_header < 0 karena timeout 5 detik habis
            break; // Keluar dari loop dengan aman ke blok cleanup
        }

        HTTP2FrameHeader head;
        if (!http2_parser_frame_header(header_buf, &head)) break;

        //fprintf(stdout, "[H2-SESSION-FRAME] Terbaca Frame Type: 0x%02X, Flags: 0x%02X, Stream ID: %u, Length: %u\n", 
        //        head.type, head.flags, head.stream_id, head.length);
        //fflush(stdout);

        size_t max_allowed_payload = (config.max_body_size > 0) ? config.max_body_size : 1048576;
        if (head.length > max_allowed_payload) {
            write_log_error("[H2-ERROR] Payload length %u exceeds config limit %zu", head.length, max_allowed_payload);
            break; 
        }

        unsigned char *payload = NULL;
        if (head.length > 0) {
            payload = malloc(head.length);
            if (!payload) break;
            
            if (h2_read_exactly(sock_client, is_tls, payload, head.length, 3000) < (ssize_t)head.length) {
                free(payload);
                break;
            }
        }

        switch (head.type) {
            case 0x00: http2_handle_data_frame(session, &head, payload); break;
            case 0x01: http2_handle_headers_frame(session, &head, payload); break;
            case 0x04: if (!(head.flags & 0x01)) send_settings_ack(sock_client, is_tls); break;
            case 0x07: 
                if (payload) free(payload); 
                goto cleanup;
            default: break;
        }

        if (payload) free(payload);
    }

cleanup:
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) { 
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            HTTP2Stream *next_node = curr->node_next; 
            if (curr->http1_compat.body_data) {
                free(curr->http1_compat.body_data);
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
    unsigned char settings[] = {
        0x00, 0x00, 0x06,       
        0x04,                   
        0x00,                   
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x08,             
        0x00, 0x00, 0x00, 0x01  
    };
    h2_write(fd, is_tls, settings, 15);
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