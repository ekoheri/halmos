#include "halmos_http2_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http2_stream.h"
#include "halmos_http2_file.h"
#include "halmos_http2_frame.h"
#include "halmos_http2_socket.h"
#include "halmos_http2_parser.h"
#include "halmos_http2_response.h"
#include "halmos_http_multipart.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi.h"
 
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <fcntl.h>      // Untuk open, O_RDONLY
#include <sys/stat.h>   // Untuk stat, struct stat, S_ISDIR
#include <sys/types.h>
 
static void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream);
static void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);
static void http2_handle_data_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);

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
        
        http2_frame_send_settings(conn->fd, session->is_tls);
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
            int flush_status = http2_socket_flush_pending_write(session);
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
            ssize_t n = http2_socket_read(sock_client, is_tls, discard_buf, to_read);
 
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
                                      http2_file_has_active_streams(session);
                    return need_write ? 4 : 2;
                }
                return 0;
            } else {
                return 0; // EOF / preface terpotong
            }
        }
 
        http2_file_flush_active_streams(session);
 
        if (session->read_state == 0) {
            size_t to_read = 9 - session->header_bytes_read;
            ssize_t n = http2_socket_read(sock_client, is_tls, session->header_buf_partial + session->header_bytes_read, to_read);
            
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
                                      http2_file_has_active_streams(session);
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
                ssize_t n = http2_socket_read(sock_client, is_tls, session->payload_buf + session->payload_bytes_read, to_read);
                
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
                                          http2_file_has_active_streams(session);
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
                        http2_frame_send_settings_ack(sock_client, is_tls);
                    }
                    break;
                case 0x06:
                    if ((head->flags & 0x01) == 0) http2_frame_send(sock_client, is_tls, 0x06, 0x01, 0, payload, head->length);
                    break;
                case 0x07:
                    return 0; // GOAWAY
                case 0x08:
                    http2_frame_handle_window_update(session, head, payload);
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
                      http2_file_has_active_streams(session);
    return need_write ? 4 : 1;
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

/*
Private (Helper)
*/
void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    //fprintf(stderr, "[H2-IN-HEADERS-START] Processing HEADERS for Stream %u (Length: %u)\n", head->stream_id, head->length);
    
    if (!session || head->stream_id == 0) return;
 
    HTTP2Stream *st = NULL;
    uint32_t bucket = http2_stream_get_bucket_fibonacci(head->stream_id);
 
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
                http2_frame_send(session->fd, session->is_tls, 0x03, 0x00, head->stream_id, error_payload, 4);
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
 
    HTTP2Stream *st = http2_stream_find(session, head->stream_id);
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
        http2_frame_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
        http2_frame_send_window_update(session->fd, session->is_tls, 0, head->length);
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
    http2_frame_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
    http2_frame_send_window_update(session->fd, session->is_tls, 0, head->length);
 
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

void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream) {
    RequestHeader *req = &stream->http1_compat;

    // =================================================================
    // 1. INTERSEPSI HANDSHAKE WEBSOCKET HTTP/2 (RFC 8441)
    // =================================================================
    if (req->is_upgrade == true) {
        //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u: Intercepting WebSocket upgrade request.\n", stream->stream_id);
        unsigned char ws_ok_payload[1] = { 0x88 }; // Indexed Header for Status 200
        
        pthread_mutex_lock(&session->streams_lock);
        http2_frame_send(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, ws_ok_payload, 1);
        pthread_mutex_unlock(&session->streams_lock);

        // --- LOG AKSES WEBSOCKET UPGRADE (Status 200) ---
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, 1);
        return; 
    }
    
    // =================================================================
    // 2. IDENTIFIKASI BACKEND (PHP / RUST / PYTHON)
    // =================================================================
    int backend_type = -1; 
    if (has_extension(req->uri, req->path_info, ".php")) { 
        backend_type = 0; 
    } 
    else if (has_extension(req->uri, req->path_info, config.rust.ext)) { 
        backend_type = 1; 
    } 
    else if (has_extension(req->uri, req->path_info, config.python.ext)) { 
        backend_type = 2; 
    }

    // MULTIPART PARSER FOR NON-FCGI
    if (backend_type == -1 && req->method[0] != '\0' && strcasecmp(req->method, "POST") == 0 && 
        req->content_type && strstr(req->content_type, "multipart/form-data")) {
        http2_multipart_parse(req);
    }

    // =================================================================
    // 3. JALUR FASTCGI BACKEND
    // =================================================================
    if (backend_type != -1) {
        //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: Routing to FastCGI backend (type: %d, URI: %s)\n", 
        //        stream->stream_id, backend_type, req->uri ? req->uri : "NULL");
        
        char *backend_data = NULL;
        ssize_t data_len = fcgi_api_request_http2(req, backend_type, req->body_data, req->content_length, &backend_data);
        
        size_t body_len = 0;

        if (data_len > 0 && backend_data) {
            char *divider = strstr(backend_data, "\r\n\r\n");
            
            if (divider) {
                *divider = '\0'; 
                char *raw_headers = backend_data;
                char *body_data = divider + 4;
                body_len = data_len - (body_data - backend_data);

                //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: FastCGI Header & Body Split (Body Len: %zu bytes)\n", 
                //        stream->stream_id, body_len);

                // 1. Kirim HEADERS Frame (END_HEADERS flag = 0x04)
                http2_response_send_complex_header(session, stream, raw_headers, 0x04);

                // 2. Kirim DATA Frame (END_STREAM flag = true)
                http2_response_send_data(session, stream, (unsigned char*)body_data, body_len, true);
            } else {
                //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: FastCGI Headers-only response.\n", stream->stream_id);
                http2_response_send_complex_header(session, stream, backend_data, 0x05); // END_STREAM | END_HEADERS
                http2_response_send_data(session, stream, NULL, 0, true);
            }
            
            // --- LOG AKSES FASTCGI SUKSES ---
            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, body_len);

            free(backend_data);

            stream->state = 4; // State CLOSED
            //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u (FastCGI) finished successfully.\n", stream->stream_id);
            return; 
        } else {
            //fprintf(stderr, "[H2-FCGI][ERR] Stream %u: FastCGI returned empty response / 502.\n", stream->stream_id);
            http2_response_send_header(session, stream, 502);
            http2_response_send_data(session, stream, "Bad Gateway", 11, true);

            // --- LOG AKSES FASTCGI BAD GATEWAY (Status 502) ---
            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 502, 11);

            stream->state = 4; 
            return;
        }
    }

    // =================================================================
    // 4. JALUR FILE STATIS
    // =================================================================
    VHostEntry *vh = (VHostEntry *)req->vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    //fprintf(stderr, "[H2-STATIC][DEBUG] Stream %u Request: URI=%s, Resolved Path=%s\n", 
    //        stream->stream_id, req->uri ? req->uri : "(null)", safe_path ? safe_path : "(null)");

    if (!safe_path || stat(safe_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        //fprintf(stderr, "[H2-STATIC][WARN] Stream %u: File not found or path invalid (%s)\n", 
        //        stream->stream_id, safe_path ? safe_path : "NULL");
        http2_response_send_header(session, stream, 404);
        http2_response_send_data(session, stream, "Not Found", 9, true);

        // --- LOG AKSES 404 NOT FOUND ---
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 404, 9);

        if (safe_path) free(safe_path);
        stream->state = 4;
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        //fprintf(stderr, "[H2-STATIC][ERR] Stream %u: Failed to open descriptor for %s\n", stream->stream_id, safe_path);
        http2_response_send_header(session, stream, 403);
        http2_response_send_data(session, stream, "Forbidden", 9, true);

        // --- LOG AKSES 403 FORBIDDEN ---
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 403, 9);

        stream->state = 4;
    } else {
        // 1. Kirim HANYA response HEADERS (200 OK)
        http2_response_send_header(session, stream, 200);

        size_t file_size = (size_t)st.st_size;

        if (file_size == 0) {
            //fprintf(stderr, "[H2-STATIC][DEBUG] Stream %u: 0-byte static file. Sending END_STREAM.\n", stream->stream_id);
            http2_response_send_data(session, stream, NULL, 0, true);
            close(fd);

            // --- LOG AKSES FILE 0-BYTE (Status 200) ---
            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, 0);

            stream->state = 4; // CLOSED
        } else {
            // 2. Jika ada isi file, DAFTARKAN FD KE STREAM (JANGAN DIBACA DI SINI!)
            pthread_mutex_lock(&session->streams_lock);
            stream->file_fd = fd;
            stream->file_size = file_size;
            stream->file_offset = 0;
            stream->is_sending_file = true;
            pthread_mutex_unlock(&session->streams_lock);

            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, file_size);

            //fprintf(stderr, "[H2-STATIC][ASYNC] Stream %u: File FD %d registered for async flushing (%zu bytes).\n", 
            //        stream->stream_id, fd, file_size);
        }
    }
    
    if (safe_path) free(safe_path);
    //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u static file setup complete.\n", stream->stream_id);
}
 

