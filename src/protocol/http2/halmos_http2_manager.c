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
/* --- TAMBAHAN: helper write-buffering (pending_write_buf) --- */
static void h2_write_or_buffer(HTTP2Session *session, int fd, bool is_tls, const unsigned char *data, size_t len);
static int http2_flush_pending_write(HTTP2Session *session);
static void http2_send_settings(int fd, bool is_tls);
static void send_settings_ack(int fd, bool is_tls);
static void http2_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment);
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
 
    // === PERBAIKAN: dulu satu kali h2_write() langsung, kalau partial/EAGAIN
    // cuma di-log lalu SISA DATANYA HILANG (frame korup/hilang diam-diam saat
    // client lambat atau window kecil). Sekarang selalu lewat
    // h2_write_or_buffer() yang menyimpan sisa yang belum terkirim ke
    // session->pending_write_buf untuk di-flush di iterasi loop berikutnya,
    // menjaga urutan byte frame tetap benar.
    halmos_conn_t *conn = core_conn_get(fd);
    HTTP2Session *session = (conn) ? (HTTP2Session *)conn->protocol_session : NULL;
 
    if (!session) {
        // Fallback: seharusnya tidak terjadi di jalur normal (session selalu
        // ada sebelum http2_send_frame dipanggil), tapi jaga-jaga saja.
        ssize_t total_sent = h2_write(fd, is_tls, total_buf, len + 9);
        if (total_sent < (ssize_t)(len + 9)) {
            write_log_error("[H2-SOCKET] Partial write (no session context) on frame type 0x%02X", type);
        }
        return;
    }
 
    h2_write_or_buffer(session, fd, is_tls, total_buf, len + 9);
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
 
void http2_session_destroy(void *sess) {
    HTTP2Session *session = (HTTP2Session *)sess;
    if (!session) return;
    
    // Kirim goaway jika diperlukan (opsional, karena socket mungkin sudah putus)
 
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
 
    if (session->dyn_table.entries) {
        free(session->dyn_table.entries);
        session->dyn_table.entries = NULL;
    }
    
    if (session->payload_buf) {
        free(session->payload_buf);
        session->payload_buf = NULL;
    }
 
    // === TAMBAHAN: bereskan sisa write backlog kalau koneksi ditutup di tengah ===
    if (session->pending_write_buf) {
        free(session->pending_write_buf);
        session->pending_write_buf = NULL;
    }
 
    pthread_mutex_destroy(&session->hpack_lock);
    pthread_mutex_destroy(&session->streams_lock);
    free(session);
}
 
int http2_manager_session(halmos_conn_t *conn) {
    if (!conn->protocol_session) {
        HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
        if (!session) return 0;
        
        session->fd = conn->fd;
        session->is_tls = (conn->ssl != NULL);
        session->out_window_size = 65535;
        session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
        session->peer_initial_window_size = 65535;
        session->dyn_table.max_size = 4096; 
        
        pthread_mutex_init(&session->hpack_lock, NULL);
        pthread_mutex_init(&session->streams_lock, NULL);
        
        conn->protocol_session = session;
        conn->protocol_session_destroy = http2_session_destroy;
        
        http2_send_settings(conn->fd, session->is_tls);
    }
    
    HTTP2Session *session = (HTTP2Session *)conn->protocol_session;
    int sock_client = conn->fd;
    bool is_tls = session->is_tls;
 
    while (1) {
        // === TAMBAHAN: Flush write backlog & cek hard error SEBELUM apa pun ===
        if (session->write_error) {
            return 0; // Hard error sudah terjadi sebelumnya, tutup koneksi
        }
        if (session->pending_write_len > session->pending_write_offset) {
            int flush_status = http2_flush_pending_write(session);
            if (flush_status < 0) {
                return 0; // Hard error saat flush
            }
            if (flush_status > 0) {
                // Masih ada sisa write backlog -> Wajib minta EPOLLIN|EPOLLOUT (Status 4)
                return 4;
            }
        }
 
        // === PERBAIKAN BUG 1: Konsumsi Client Connection Preface (24 byte) ===
        if (session->preface_bytes_read < 24) {
            unsigned char discard_buf[24];
            size_t to_read = 24 - session->preface_bytes_read;
            ssize_t n = h2_read(sock_client, is_tls, discard_buf, to_read);
 
            if (n > 0) {
                session->preface_bytes_read += n;
                if (session->preface_bytes_read < 24) {
                    continue; 
                }
            } else if (n < 0) {
                bool retry = false;
                if (is_tls) {
                    int err = SSL_get_error(conn->ssl, n);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) retry = true;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    retry = true;
                }
                if (retry) {
                    // Jika ada pending write atau file aktif, kembalikan 4 (EPOLLIN|EPOLLOUT), jika tidak kembalikan 2
                    bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                                      http2_has_active_file_streams(session);
                    return need_write ? 4 : 2;
                }
                return 0;
            } else {
                return 0; // EOF / preface terpotong
            }
        }
 
        http2_flush_active_streams_file(session);
 
        if (session->read_state == 0) {
            size_t to_read = 9 - session->header_bytes_read;
            ssize_t n = h2_read(sock_client, is_tls, session->header_buf_partial + session->header_bytes_read, to_read);
            
            if (n > 0) {
                session->header_bytes_read += n;
                if (session->header_bytes_read == 9) {
                    if (!http2_parser_frame_header(session->header_buf_partial, &session->current_frame_head)) {
                        return 0; 
                    }
                    session->read_state = 1;
                    session->payload_bytes_read = 0;
                    if (session->current_frame_head.length > 0) {
                        size_t max_allowed_payload = (config.max_body_size > 0) 
                                                      ? config.max_body_size : 1048576;
                        if (session->current_frame_head.length > max_allowed_payload) {
                            write_log_error("[H2-ERROR] Frame payload length %u exceeds limit (%zu) on FD %d", 
                                            session->current_frame_head.length, max_allowed_payload, sock_client);
                            return 0; 
                        }
                        session->payload_buf = malloc(session->current_frame_head.length);
                        if (!session->payload_buf) return 0;
                    }
                }
            } else if (n < 0) {
                bool retry = false;
                if (is_tls) {
                     int err = SSL_get_error(conn->ssl, n);
                     if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) retry = true;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                     retry = true;
                }
                if (retry) {
                    bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                                      http2_has_active_file_streams(session);
                    return need_write ? 4 : 2; 
                }
                return 0;
            } else {
                if (session->header_bytes_read == 0) return 0; 
                return 0; 
            }
        }
 
        if (session->read_state == 1) {
            if (session->current_frame_head.length > 0) {
                size_t to_read = session->current_frame_head.length - session->payload_bytes_read;
                ssize_t n = h2_read(sock_client, is_tls, session->payload_buf + session->payload_bytes_read, to_read);
                
                if (n > 0) {
                    session->payload_bytes_read += n;
                    if (session->payload_bytes_read < session->current_frame_head.length) {
                        continue;
                    }
                } else if (n < 0) {
                    bool retry = false;
                    if (is_tls) {
                         int err = SSL_get_error(conn->ssl, n);
                         if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) retry = true;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                         retry = true;
                    }
                    if (retry) {
                        bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                                          http2_has_active_file_streams(session);
                        return need_write ? 4 : 2; 
                    }
                    return 0;
                } else {
                    return 0; 
                }
            }
            
            // Frame lengkap, proses
            HTTP2FrameHeader *head = &session->current_frame_head;
            unsigned char *payload = session->payload_buf;
            
            switch (head->type) {
                case 0x00: http2_handle_data_frame(session, head, payload); break;
                case 0x01: http2_handle_headers_frame(session, head, payload); break;
                case 0x03: {
                    pthread_mutex_lock(&session->streams_lock);
                    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
                        HTTP2Stream *curr = session->streams_hash[i];
                        while (curr != NULL) {
                            if (curr->stream_id == head->stream_id) {
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
                case 0x04:
                    if (!(head->flags & 0x01) && payload && head->length >= 6) {
                        for (uint32_t idx = 0; idx + 6 <= head->length; idx += 6) {
                            uint16_t id = (payload[idx] << 8) | payload[idx + 1];
                            uint32_t val = (payload[idx + 2] << 24) | (payload[idx + 3] << 16) | (payload[idx + 4] << 8) | payload[idx + 5];
                            if (id == 0x0004) {
                                int32_t delta = (int32_t)val - (int32_t)session->peer_initial_window_size;
                                session->peer_initial_window_size = val;
                                pthread_mutex_lock(&session->streams_lock);
                                for (int b = 0; b < HTTP2_STREAM_BUCKETS; b++) {
                                    HTTP2Stream *s = session->streams_hash[b];
                                    while (s) { s->out_window_size += delta; s = s->node_next; }
                                }
                                pthread_mutex_unlock(&session->streams_lock);
                            }
                        }
                        send_settings_ack(sock_client, is_tls);
                    }
                    break;
                case 0x06:
                    if ((head->flags & 0x01) == 0) http2_send_frame(sock_client, is_tls, 0x06, 0x01, 0, payload, head->length);
                    break;
                case 0x07:
                    return 0; // GOAWAY
                case 0x08:
                    http2_handle_window_update_frame(session, head, payload);
                    break;
            }
            
            if (session->payload_buf) {
                free(session->payload_buf);
                session->payload_buf = NULL;
            }
            
            session->read_state = 0;
            session->header_bytes_read = 0;
        }
    }
    
    // Return akhir sesi (jika loop selesai/keluar)
    bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                      http2_has_active_file_streams(session);
    return need_write ? 4 : 1;
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
 
/**
 * === TAMBAHAN: Write-buffering supaya frame HTTP/2 tidak hilang diam-diam ===
 *
 * Fast path: kalau BELUM ada backlog tertunda, langsung coba write() sekali.
 * Kalau habis (fully sent), selesai, tidak ada copy sama sekali.
 * Kalau parsial/EAGAIN, atau MEMANG sudah ada backlog dari sebelumnya (harus
 * antre di belakang supaya urutan byte tetap benar), sisanya di-copy ke
 * session->pending_write_buf untuk di-flush nanti oleh
 * http2_flush_pending_write() di awal iterasi loop berikutnya.
 *
 * Tidak butuh lock terpisah: dipanggil hanya dari thread yang sedang
 * memegang conn->io_lock sepanjang durasi dispatch (sama seperti semua
 * field resumable lain di HTTP2Session).
 */
void h2_write_or_buffer(HTTP2Session *session, int fd, bool is_tls, const unsigned char *data, size_t len) {
    if (!session || len == 0) return;
 
    size_t already_sent = 0;
 
    if (session->pending_write_len <= session->pending_write_offset) {
        // Belum ada backlog - coba kirim langsung dulu.
        ssize_t n = h2_write(fd, is_tls, data, len);
 
        if (n == (ssize_t)len) {
            return; // Terkirim penuh, tidak perlu buffer apa pun.
        }
 
        if (n < 0) {
            bool retry = false;
            // === PERBAIKAN: ssl_send() sekarang mengembalikan sentinel
            // SENDIRI (-EAGAIN/-EWOULDBLOCK untuk retry, -1 untuk error
            // fatal) - BUKAN nilai mentah dari SSL_write(). Memanggil
            // SSL_get_error(ssl, n) di sini SALAH: fungsi itu butuh return
            // value ASLI dari operasi SSL terakhir, bukan sentinel buatan
            // sendiri. Dulu ini bisa salah baca EAGAIN sebagai hard error
            // dan menutup koneksi HTTP/2 prematur di tengah transfer.
            if (is_tls) {
                if (n == -EAGAIN || n == -EWOULDBLOCK) retry = true;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                retry = true;
            }
 
            if (!retry) {
                write_log_error("[H2-SOCKET] Hard write error on FD %d, marking session failed", fd);
                session->write_error = true;
                return;
            }
            n = 0; // Belum ada satu byte pun yang terkirim
        }
 
        already_sent = (size_t)n;
    }
 
    size_t remaining = len - already_sent;
    if (remaining == 0) return;
 
    // Gabungkan sisa backlog lama (kalau ada) + sisa data baru yang belum terkirim.
    size_t old_unsent = session->pending_write_len - session->pending_write_offset;
    size_t new_total = old_unsent + remaining;
 
    unsigned char *new_buf = malloc(new_total);
    if (!new_buf) {
        write_log_error("[H2-SOCKET] Malloc failed for pending write buffer on FD %d", fd);
        session->write_error = true;
        return;
    }
 
    if (old_unsent > 0) {
        memcpy(new_buf, session->pending_write_buf + session->pending_write_offset, old_unsent);
    }
    memcpy(new_buf + old_unsent, data + already_sent, remaining);
 
    if (session->pending_write_buf) free(session->pending_write_buf);
    session->pending_write_buf = new_buf;
    session->pending_write_len = new_total;
    session->pending_write_offset = 0;
}
 
/**
 * Coba tuntaskan backlog yang ada.
 * Return: 0 = selesai penuh (buffer sudah dibebaskan), 1 = masih ada sisa
 * (EAGAIN, caller harus rearm & coba lagi nanti), -1 = hard error (caller
 * harus tutup koneksi).
 */
int http2_flush_pending_write(HTTP2Session *session) {
    if (!session) return -1;
    if (session->pending_write_len <= session->pending_write_offset) return 0;
 
    size_t remaining = session->pending_write_len - session->pending_write_offset;
    ssize_t n = h2_write(session->fd, session->is_tls,
                         session->pending_write_buf + session->pending_write_offset, remaining);
 
    if (n > 0) {
        session->pending_write_offset += (size_t)n;
        if (session->pending_write_offset >= session->pending_write_len) {
            free(session->pending_write_buf);
            session->pending_write_buf = NULL;
            session->pending_write_len = 0;
            session->pending_write_offset = 0;
            return 0;
        }
        return 1; // Masih ada sisa
    }
 
    if (n < 0) {
        bool retry = false;
        // === PERBAIKAN: sama seperti di h2_write_or_buffer() - ssl_send()
        // sudah mengklasifikasi sendiri (-EAGAIN/-EWOULDBLOCK vs -1), tidak
        // perlu/boleh dipanggilkan SSL_get_error() lagi di atasnya.
        if (session->is_tls) {
            if (n == -EAGAIN || n == -EWOULDBLOCK) retry = true;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retry = true;
        }
        if (retry) return 1;
 
        write_log_error("[H2-SOCKET] Hard write error while flushing pending buffer on FD %d", session->fd);
        return -1;
    }
 
    return 1; // n == 0, jarang terjadi di socket non-blocking, anggap belum selesai
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
