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
static HTTP2Stream* find_stream_unlocked(HTTP2Session *session, uint32_t id);
static HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id);
/* --- TAMBAHAN DEKLARASI HELPER --- */
static void http2_handle_window_update_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);
static void http2_flush_active_streams_file(HTTP2Session *session) ;
static bool http2_has_active_file_streams(HTTP2Session *session);

void http2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
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

    //fprintf(stderr, "[SOCKET-OUT] Type: 0x%02X | Stream: %u | Length: %u | Flags: 0x%02X", 
    //        type, stream_id, len, flags);
            
    //if (type == 0x01 && len > 0 && payload != NULL) { 
    //    const unsigned char *p = (const unsigned char *)payload;
    //    fprintf(stderr, " | First Payload Byte: 0x%02X", p[0]);
    //}
    //fprintf(stderr, "\n");

    ssize_t total_sent = h2_write(fd, is_tls, total_buf, len + 9);
    if (total_sent < (ssize_t)(len + 9)) {
        write_log_error("[H2-SOCKET] Partial write on frame type 0x%02X", type);
    }
}

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    //fprintf(stderr, "[H2-IN-HEADERS-START] Processing HEADERS for Stream %u (Length: %u)\n", head->stream_id, head->length);
    
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
        st->out_window_size = session->peer_initial_window_size; // <--- PERBAIKAN: Default RFC 7540 Stream Window
        st->file_fd = -1;            // <--- PERBAIKAN: Pastikan FD file bernilai -1
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

    //fprintf(stderr, "[H2-IN-HEADERS] Stream %u | Clean HPACK Len: %zu | Flags: 0x%02X\n", 
    //        head->stream_id, hpack_len, head->flags);

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
            //fprintf(stderr, "[DEBUG-SYNC] Executing WebSocket Upgrade Bridge for Stream %u\n", head->stream_id);
            http2_response_routing_bridge(session, st);
            return;
        }

        // 2. JALUR REQUEST GET / TANPA BODY DATA (END_STREAM = 0x01)
        if (head->flags & 0x01) { 
            //fprintf(stderr, "[H2-IN-HEADERS] END_STREAM detected on Stream %u. Crossing to Bridge...\n", head->stream_id);
            
            pthread_mutex_lock(&session->streams_lock);
            // Tandai client sudah selesai kirim header (Half Closed Remote = 2)
            st->state = 2; 
            pthread_mutex_unlock(&session->streams_lock);

            //fprintf(stderr, "[DEBUG-SYNC] Calling routing bridge from headers frame handler...\n");
            http2_response_routing_bridge(session, st);
            //fprintf(stderr, "[DEBUG-SYNC] Routing bridge returned control to headers frame handler.\n");

            // BARIS st->state = 4 KITA HAPUS TOTAL DI SINI.
        }
    } else {
        //fprintf(stderr, "[H2-IN-HEADERS-ERR] HPACK Parse failed for Stream %u!\n", head->stream_id);
    }

    //fprintf(stderr, "[H2-IN-HEADERS-END] Finished processing HEADERS for Stream %u\n", head->stream_id);
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
    //fprintf(stderr, "\n=======================================================\n");
    //fprintf(stderr, "[H2-SESSION-START] New HTTP/2 Session initialized on Sock FD: %d (TLS: %s)\n", 
    //        sock_client, is_tls ? "YES" : "NO");
    //fprintf(stderr, "=======================================================\n");

    HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
    if (!session) {
        //fprintf(stderr, "[H2-SESSION-ERR] Malloc failed for HTTP2Session!\n");
        return 0;
    }

    session->fd = sock_client;
    session->is_tls = is_tls;
    session->out_window_size = 65535; // <--- PERBAIKAN: Default Connection Window
    session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
    session->peer_initial_window_size = 65535;
    session->dyn_table.max_size = 4096; // <--- PERBAIKAN: Set max table size HPACK (biasanya 4096) 

    pthread_mutex_init(&session->hpack_lock, NULL);
    pthread_mutex_init(&session->streams_lock, NULL); 

    // 1. Kirim SETTINGS Server awal
    http2_send_settings(sock_client, is_tls);
    
    // 2. Baca Client Connection Preface (24 Bytes)
    char preface[24];
    //fprintf(stderr, "[H2-SESSION] Waiting for 24-byte Client Connection Preface...\n");
    ssize_t read_preface = h2_read_exactly(sock_client, is_tls, preface, 24, 5000);
    
    if (read_preface < 24) {
        //fprintf(stderr, "[H2-SESSION-ERR] Preface incomplete or timeout! Read: %zd/24 bytes. Aborting.\n", read_preface);
        goto cleanup;
    }
    //fprintf(stderr, "[H2-SESSION-OK] Client Preface received successfully.\n");

    // 3. Event Loop Pembacaan Frame HTTP/2
    uint32_t frame_count = 0;

    while (1) {
        unsigned char header_buf[9];
        
        // 1. Pompa chunk file sebelum membaca socket
        http2_flush_active_streams_file(session);

        // 2. Tentukan timeout berdasarkan status streaming
        bool has_file = http2_has_active_file_streams(session);
        
        // Jika sedang kirim file, jangan memblokir socket! Gunakan timeout 1ms.
        // Jika IDLE, baru boleh blocking (misal 10000ms / 10 detik).
        int read_timeout = has_file ? 1 : 10000;

        ssize_t n_header = h2_read_exactly(sock_client, is_tls, header_buf, 9, read_timeout);
        
        if (n_header == 0) {
            //fprintf(stderr, "[H2-SESSION-CLOSE] Client closed TCP/TLS connection gracefully (EOF).\n");
            break; 
        } 
        else if (n_header < 0) {
            // Jika return -1 karena timeout (EAGAIN), DAN kita sedang punya file aktif, IT'S OK!
            // Jangan break! Lanjutkan loop untuk memompa chunk berikutnya.
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == 0) {
                errno = 0; // Reset errno
                continue; 
            }
            
            // Jika bukan karena timeout streaming, ini error asli
            //fprintf(stderr, "[H2-SESSION-ERR] Read error / timeout on FD %d (errno: %d)\n", sock_client, errno);
            break;
        } 
        else if (n_header > 0 && n_header < 9) {
            //fprintf(stderr, "[H2-SESSION-ERR] Incomplete 9-byte frame header read (%zd bytes). Disconnecting.\n", n_header);
            break;
        }
        else if (n_header == 9) {
            frame_count++;
            HTTP2FrameHeader head;
            if (!http2_parser_frame_header(header_buf, &head)) {
                //fprintf(stderr, "[H2-SESSION-ERR] Failed to parse 9-byte HTTP/2 Frame Header!\n");
                break;
            }

            //fprintf(stderr, "[H2-FRAME-IN #%u] Type: 0x%02X | Flags: 0x%02X | Stream: %u | Length: %u\n", 
            //        frame_count, head.type, head.flags, head.stream_id, head.length);

            size_t max_allowed_payload = (config.max_body_size > 0) ? config.max_body_size : 1048576;
            if (head.length > max_allowed_payload) {
                //fprintf(stderr, "[H2-SESSION-ERR] Payload length %u exceeds limit!\n", head.length);
                break; 
            }

            unsigned char *payload = NULL;
            if (head.length > 0) {
                payload = malloc(head.length);
                if (!payload) break;
                
                ssize_t n_payload = h2_read_exactly(sock_client, is_tls, payload, head.length, 5000);
                if (n_payload < (ssize_t)head.length) {
                    //fprintf(stderr, "[H2-SESSION-ERR] Payload timeout/incomplete!\n");
                    free(payload);
                    break;
                }
            }

            switch (head.type) {
                case 0x00: // DATA
                    http2_handle_data_frame(session, &head, payload); 
                    break;
                case 0x01: // HEADERS
                    http2_handle_headers_frame(session, &head, payload); 
                    break;
                case 0x03: { // RST_STREAM
                    //fprintf(stderr, "[H2-EXEC] Received RST_STREAM for Stream %u. Cleaning stream resources.\n", head.stream_id);
                    
                    pthread_mutex_lock(&session->streams_lock);
                    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
                        HTTP2Stream *curr = session->streams_hash[i];
                        while (curr != NULL) {
                            if (curr->stream_id == head.stream_id) {
                                if (curr->file_fd >= 0) {
                                    close(curr->file_fd);
                                    curr->file_fd = -1;
                                }
                                curr->is_sending_file = false;
                                curr->state = HTTP2_STATE_CLOSED;
                                break;
                            }
                            curr = curr->node_next;
                        }
                    }
                    pthread_mutex_unlock(&session->streams_lock);
                    break;
                }
                case 0x04: // SETTINGS
                    if (!(head.flags & 0x01) && payload && head.length >= 6) {
                        // Iterasi payload SETTINGS (tiap setting berukuran 6 bytes: 2 byte ID + 4 byte Value)
                        for (uint32_t idx = 0; idx + 6 <= head.length; idx += 6) {
                            uint16_t id = (payload[idx] << 8) | payload[idx + 1];
                            uint32_t val = (payload[idx + 2] << 24) | (payload[idx + 3] << 16) |
                                           (payload[idx + 4] << 8)  | payload[idx + 5];

                            // ID 0x0004 = SETTINGS_INITIAL_WINDOW_SIZE
                            if (id == 0x0004) {
                                int32_t delta = (int32_t)val - (int32_t)session->peer_initial_window_size;
                                session->peer_initial_window_size = val;

                                // Update kredit window pada seluruh active streams
                                pthread_mutex_lock(&session->streams_lock);
                                for (int b = 0; b < HTTP2_STREAM_BUCKETS; b++) {
                                    HTTP2Stream *s = session->streams_hash[b];
                                    while (s) {
                                        s->out_window_size += delta;
                                        s = s->node_next;
                                    }
                                }
                                pthread_mutex_unlock(&session->streams_lock);
                            }
                        }
                        send_settings_ack(sock_client, is_tls); 
                    }
                    break;
                case 0x06: // PING Frame
                    if ((head.flags & 0x01) == 0) {
                        http2_send_frame(session->fd, session->is_tls, 0x06, 0x01, 0, payload, head.length);
                    }
                    break;
                case 0x07: // GOAWAY
                    if (payload) free(payload); 
                    goto cleanup;
                case 0x08: // WINDOW_UPDATE
                    http2_handle_window_update_frame(session, &head, payload);
                    break;
                default: 
                    //fprintf(stderr, "[H2-EXEC] Unhandled Frame Type: 0x%02X (Ignored)\n", head.type);
                    break;
            }

            if (payload) free(payload);
        }

        // Pompa lagi setelah memproses frame
        http2_flush_active_streams_file(session);
    }

cleanup:
    //fprintf(stderr, "[H2-SESSION-CLEANUP] Destroying Session resources on FD %d...\n", sock_client);

    // Kuras sisa file streaming jika masih ada yang menggantung sebelum mematikan session
    http2_flush_active_streams_file(session);

    uint8_t goaway_frame[17] = {
        0x00, 0x00, 0x08,        // Length: 8 bytes
        0x07,                    // Type: GOAWAY (0x07)
        0x00,                    // Flags: 0x00
        0x00, 0x00, 0x00, 0x00,  // Stream ID: 0
        0x00, 0x00, 0x00, 0x01,  // Last-Stream-ID: 1
        0x00, 0x00, 0x00, 0x00   // Error Code: NO_ERROR (0x00)
    };
    h2_write(sock_client, is_tls, goaway_frame, sizeof(goaway_frame));
    
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) { 
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            HTTP2Stream *next_node = curr->node_next; 

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

    /*
    if (session->dyn_table.entries) {
        for (uint32_t i = 0; i < session->dyn_table.count; i++) {
            if (session->dyn_table.entries[i].name) free(session->dyn_table.entries[i].name);
            if (session->dyn_table.entries[i].value) free(session->dyn_table.entries[i].value);
        }
        free(session->dyn_table.entries);
    }*/

    if (session->dyn_table.entries) {
        free(session->dyn_table.entries);
        session->dyn_table.entries = NULL;
    }

    pthread_mutex_destroy(&session->hpack_lock);
    pthread_mutex_destroy(&session->streams_lock);
    free(session);

    //fprintf(stderr, "[H2-SESSION-END] Session cleanly closed on FD %d.\n=======================================================\n\n", sock_client);
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
    
    //fprintf(stderr, "[H2-SESSION] Sending Initial SETTINGS Frame (27 bytes)...\n");
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

    struct timespec start_time, current_time;
    if (timeout_ms > 0) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    while (total_read < len) {
        // Hapus duplikasi panggilan h2_read di sini
        ssize_t n = h2_read(fd, is_tls, ptr + total_read, len - total_read);
    
        if (n > 0) {
            total_read += n;
            if (total_read == len) {
                return (ssize_t)total_read;
            }
        } else if (n == 0) {
            // EOF dari client
            if (total_read == 0) {
                return 0; // Graceful EOF
            }
            // Truncated payload/header (Client putus mendadak di tengah stream)
            return -1; 
        } else {
            bool retry_it = false;
            
            if (is_tls) {
                SSL *ssl = ssl_get_for_fd(fd);
                if (ssl) {
                    int err_code = SSL_get_error(ssl, (int)n);
                    if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) {
                        retry_it = true;
                    }
                }
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    retry_it = true;
                }
            }

            if (retry_it) {
                if (timeout_ms == 0) {
                    return -1; 
                }

                int poll_timeout = timeout_ms;
                if (timeout_ms > 0) {
                    clock_gettime(CLOCK_MONOTONIC, &current_time);
                    long elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                                      (current_time.tv_nsec - start_time.tv_nsec) / 1000000;
                    
                    if (elapsed_ms >= timeout_ms) {
                        return -1; // Timeout
                    }
                    poll_timeout = timeout_ms - (int)elapsed_ms;
                }

                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                int res = poll(&pfd, 1, poll_timeout);
                
                if (res > 0) {
                    continue; 
                } else {
                    return -1;
                }
            }
            
            return -1;
        }
    }
    
    return (ssize_t)total_read;
}

// Helper internal tanpa locking (asumsi caller sudah memegang streams_lock)
HTTP2Stream* find_stream_unlocked(HTTP2Session *session, uint32_t id) {
    if (!session || id == 0) return NULL;
    uint32_t bucket = get_bucket_fibonacci(id);
    HTTP2Stream *curr = session->streams_hash[bucket];
    while (curr != NULL) {
        if (curr->stream_id == id) {
            return curr;
        }
        curr = curr->node_next;
    }
    return NULL;
}

HTTP2Stream* find_stream(HTTP2Session *session, uint32_t id) {
    if (!session) return NULL;
    pthread_mutex_lock(&session->streams_lock);
    HTTP2Stream *st = find_stream_unlocked(session, id);
    pthread_mutex_unlock(&session->streams_lock);
    return st;
}

void http2_handle_window_update_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session || !payload || head->length < 4) return;

    // Byte ke-0 di-AND dengan 0x7F untuk mengabaikan Reserved Bit (R)
    uint32_t increment = ((payload[0] & 0x7F) << 24) |
                         (payload[1] << 16) |
                         (payload[2] << 8)  |
                          payload[3];

    if (increment == 0) {
        // RFC 7540 Section 6.9: Increment 0 adalah PROTOCOL_ERROR
        write_log_error("[H2-WINDOW] Error: Window update increment of 0 on stream %u", head->stream_id);
        return;
    }

    pthread_mutex_lock(&session->streams_lock);

    if (head->stream_id == 0) {
        // Stream ID 0 -> Connection-level Window
        session->out_window_size += increment;
        //fprintf(stderr, "[H2-WINDOW] Connection Window Updated -> New Credit: %d bytes\n", session->out_window_size);
    } else {
        // Stream ID > 0 -> Stream-level Window
        HTTP2Stream *st = find_stream_unlocked(session, head->stream_id);
        if (st) {
            st->out_window_size += increment;
            //fprintf(stderr, "[H2-WINDOW] Stream %u Window Updated -> New Credit: %d bytes\n", 
            //        head->stream_id, st->out_window_size);
        }
    }

    pthread_mutex_unlock(&session->streams_lock);
}

void http2_flush_active_streams_file(HTTP2Session *session) {
    if (!session) return;

    uint32_t active_ids[256];
    int active_count = 0;

    // 1. Kumpulkan stream aktif under lock
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            if (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED) {
                if (active_count < 256) {
                    active_ids[active_count++] = curr->stream_id;
                }
            }
            curr = curr->node_next;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);

    // 2. Iterasi stream dan periksa Flow Control Credit
    for (int k = 0; k < active_count; k++) {
        uint32_t target_sid = active_ids[k];
        
        int file_fd = -1;
        off_t offset = 0;
        off_t total_size = 0;
        int32_t conn_win = 0;
        int32_t stream_win = 0;
        bool valid = false;

        // Ambil snapshot metadata & window credit
        pthread_mutex_lock(&session->streams_lock);
        HTTP2Stream *st = find_stream_unlocked(session, target_sid);
        if (st && st->is_sending_file && st->file_fd >= 0 && st->state != HTTP2_STATE_CLOSED) {
            file_fd = st->file_fd;
            offset = st->file_offset;
            total_size = st->file_size;
            conn_win = session->out_window_size;
            stream_win = st->out_window_size;
            valid = true;
        }
        pthread_mutex_unlock(&session->streams_lock);

        if (!valid || file_fd < 0 || offset >= total_size) continue;

        // CHECK 1: Apabila connection window atau stream window habis (<= 0), tunda pengiriman!
        if (conn_win <= 0 || stream_win <= 0) {
            //fprintf(stderr, "[H2-FLOW-CONTROL] Stalled Stream %u | Conn Window: %d, Stream Window: %d\n", 
            //        target_sid, conn_win, stream_win);
            continue; // Skip stream ini sampai client mengirim WINDOW_UPDATE
        }

        // Hitung sisa bytes di disk
        off_t bytes_remaining = total_size - offset;

        // CHECK 2: Cari nilai terkecil antara MAX_FRAME_SIZE, Conn Window, Stream Window, dan sisa File
        uint32_t max_allowed = HTTP2_MAX_FRAME_SIZE; 
        if ((int32_t)max_allowed > conn_win) max_allowed = (uint32_t)conn_win;
        if ((int32_t)max_allowed > stream_win) max_allowed = (uint32_t)stream_win;
        if ((off_t)max_allowed > bytes_remaining) max_allowed = (uint32_t)bytes_remaining;

        if (max_allowed == 0) continue;

        // Baca disk secara Non-blocking via pread
        unsigned char buf[HTTP2_MAX_FRAME_SIZE];
        ssize_t n_read = pread(file_fd, buf, max_allowed, offset);

        if (n_read <= 0) {
            pthread_mutex_lock(&session->streams_lock);
            st = find_stream_unlocked(session, target_sid);
            if (st) {
                if (st->file_fd >= 0) close(st->file_fd);
                st->file_fd = -1;
                st->is_sending_file = false;
                st->state = HTTP2_STATE_CLOSED;
            }
            pthread_mutex_unlock(&session->streams_lock);
            continue;
        }

        uint8_t flags = 0x00;
        if ((offset + n_read) >= total_size) {
            flags = 0x01; // END_STREAM
        }

        // Kirim frame DATA ke socket
        http2_send_frame(session->fd, session->is_tls, 0x00, flags, target_sid, buf, (uint32_t)n_read);

        // CHECK 3: Potong (deduct) kredit window sejumlah byte payload yang dikirim (n_read)
        pthread_mutex_lock(&session->streams_lock);
        session->out_window_size -= (int32_t)n_read;
        
        st = find_stream_unlocked(session, target_sid);
        if (st) {
            st->out_window_size -= (int32_t)n_read;
            st->file_offset += n_read;
            if (st->file_offset >= st->file_size) {
                if (st->file_fd >= 0) close(st->file_fd);
                st->file_fd = -1;
                st->is_sending_file = false;
                st->state = HTTP2_STATE_CLOSED;
            }
        }
        pthread_mutex_unlock(&session->streams_lock);
    }
}

bool http2_has_active_file_streams(HTTP2Session *session) {
    if (!session) return false;
    bool has_file = false;

    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            if (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED) {
                has_file = true;
                break;
            }
            curr = curr->node_next;
        }
        if (has_file) break;
    }
    pthread_mutex_unlock(&session->streams_lock);
    
    return has_file;
}