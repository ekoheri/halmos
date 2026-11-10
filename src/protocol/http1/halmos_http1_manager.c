#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http1_parser.h"
#include "halmos_http1_response.h"
#include "halmos_http_vhost.h"
#include "halmos_http_utils.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"
#include "halmos_errors.h"
#include "halmos_ws_system.h"

#include "halmos_fcgi_event_loop.h"
#include "halmos_fcgi_proto.h"
#include "halmos_fcgi_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/epoll.h>

// Helper 1A: Menangani State Membaca Header HTTP
static int handle_read_headers_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls);

// Helper 1B: Menangani State Membaca Body Request
static int handle_read_body_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls) ;

// Helper 2: Menangani routimg (ke websocket, fastCGI, file statis)
static int http1_manager_routing_bridge(halmos_conn_t *conn, HTTP1Session *session);

// Helper 3: Menangani State Pemrosesan & Pengiriman FastCGI
static int handle_fcgi_processing_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls);

// Helper 4: Menangani State Pengiriman File Statis
static int handle_static_file_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls);

int http1_manager_session(halmos_conn_t *conn) {
    if (!conn->protocol_session) {
        HTTP1Session *s = calloc(1, sizeof(HTTP1Session));
        s->buf_capacity = (config.request_buffer_size > 0) ? config.request_buffer_size : 8192;
        s->buffer = malloc(s->buf_capacity);
        if (s->buffer) s->buffer[0] = '\0';
        s->state = STATE_READ_HEADERS;
        s->file_fd = -1;
        conn->protocol_session = s;
        conn->protocol_session_destroy = http1_session_destroy;
    }
    
    HTTP1Session *session = (HTTP1Session *)conn->protocol_session;
    int sock_client = conn->fd;
    bool is_tls = (conn->ssl != NULL);

    struct timespec cpu_tick_start;
    core_adaptive_telemetry_tick_begin(&session->telemetry, &cpu_tick_start);

    int res = 2; // Default return

    // =========================================================================
    // 1A. STATE: BACA REQUEST HEADER
    // =========================================================================
    if (session->state == STATE_READ_HEADERS) {
        res = handle_read_headers_state(conn, session, sock_client, is_tls);
        if (res <= 0 || res == 2) goto done;
    }

    // =========================================================================
    // 1B. STATE: BACA BODY REQUEST
    // =========================================================================
    if (session->state == STATE_READ_BODY) {
        res = handle_read_body_state(conn, session, sock_client, is_tls);
        if (res <= 0 || res == 2) goto done;
    }
        
    // =========================================================================
    // 2. STATE: HANDLE REQUEST & PREPARE RESPONSE
    // =========================================================================
    if (session->state == STATE_HANDLE_REQUEST) {
        res = http1_manager_routing_bridge(conn, session);
        goto done;
    }

    // =========================================================================
    // 3. STATE: PEMROSESAN FASTCGI BERBASIS FSM
    // =========================================================================
    if (session->state == STATE_FCGI_PROCESSING) {
        res = handle_fcgi_processing_state(conn, session, sock_client, is_tls);
        goto done;
    }

    // =========================================================================
    // 4. STATE: PENGIRIMAN FILE STATIS (EPOLLOUT)
    // =========================================================================
    if (session->state == STATE_SEND_STATIC_FILE) {
        res = handle_static_file_state(conn, session, sock_client, is_tls);
        goto done;
    }

done:
    // AKHIRI TICK: Dijamin 100% terpanggil terlepas dari state mana pun yang selesai!
    core_adaptive_telemetry_tick_end(&session->telemetry, &cpu_tick_start);
    
    return res;
}

void http1_session_destroy(void *session) {
    HTTP1Session *s = (HTTP1Session *)session;
    if (!s) return;

    // Panggil fungsi finalisasi terpusat
    core_adaptive_telemetry_finalize(&s->telemetry);
    // ========================================================

    if (s->buffer) free(s->buffer);
    if (s->file_fd >= 0) close(s->file_fd);

    // Bersihkan sesi FCGI jika masih aktif
    if (s->fcgi_session_id >= 0) {
        FCGI_Session *fs = fcgi_session_slot_get(s->fcgi_session_id);
        if (fs) {
            // Putuskan pointer SSL & socket agar worker tahu koneksi sudah putus
            pthread_mutex_lock(&fs->lock);
            fs->ssl_conn = NULL;
            fs->sock_client = -1;
            pthread_mutex_unlock(&fs->lock);

            fcgi_session_release(fs);
        }
        s->fcgi_session_id = -1;
    }

    if (s->fcgi_write_buf) {
        free(s->fcgi_write_buf);
        s->fcgi_write_buf = NULL;
    }

    http1_parser_free_memory(&s->req);
    free(s);
}

// =========================================================================
// Helper 1A: Menangani State Membaca Header HTTP
// =========================================================================
int handle_read_headers_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls) {
    bool should_retry = false;
    bool connection_closed = false;

    while (1) {
        if (session->buf_len >= session->buf_capacity - 1) {
            size_t new_cap = session->buf_capacity * 2;
            char *new_buf = realloc(session->buffer, new_cap);
            if (!new_buf) return -1;
            
            if (new_buf != session->buffer) {
                ptrdiff_t diff = new_buf - session->buffer;
                if (session->req.uri)          session->req.uri += diff;
                if (session->req.directory)    session->req.directory += diff;
                if (session->req.query_string) session->req.query_string += diff;
                if (session->req.host)         session->req.host += diff;
                if (session->req.content_type) session->req.content_type += diff;
                if (session->req.cookie_data)  session->req.cookie_data += diff;
                if (session->req.body_data)    session->req.body_data = (void*)((char*)session->req.body_data + diff);
                if (session->req.path_info)    session->req.path_info += diff;
            }
            session->buffer = new_buf;
            session->buf_capacity = new_cap;
        }

        size_t to_read = session->buf_capacity - session->buf_len - 1;
        ssize_t n = is_tls ? SSL_read(conn->ssl, session->buffer + session->buf_len, (int)to_read)
                           : recv(sock_client, session->buffer + session->buf_len, to_read, 0);
        
        if (n > 0) {
            session->buf_len += n;
            session->buffer[session->buf_len] = '\0';
            
            if (strstr(session->buffer, "\r\n\r\n") != NULL) {
                break; 
            }
        } else if (n < 0) {
            if (is_tls) {
                 int err = SSL_get_error(conn->ssl, (int)n);
                 if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                     should_retry = true;
                 }
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                 should_retry = true;
            }
            break;
        } else { // n == 0
            connection_closed = true;
            break;
        }
    }

    if (connection_closed && session->buf_len == 0) return 0;

    if (strstr(session->buffer, "\r\n\r\n") == NULL) {
        if (connection_closed) return 0;
        if (should_retry) return 2; // WANT_READ (EPOLLIN)
        return -1;
    }

    session->req.is_tls = is_tls;
    
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(sock_client, (struct sockaddr*)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s_addr = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &s_addr->sin_addr, session->req.client_ip, sizeof(session->req.client_ip));
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &s_addr->sin6_addr, session->req.client_ip, sizeof(session->req.client_ip));
        }
    }

    if (!http1_parser_parse_header(session->buffer, session->buf_len, &session->req) || !session->req.is_valid) {
        http1_response_send_mem(sock_client, 400, "Bad Request", "400 Bad Request", false, is_tls);
        return 0;
    }

    if (session->req.content_length > 0) {
        session->state = STATE_READ_BODY;
    } else {
        session->state = STATE_HANDLE_REQUEST;
    }
    return 1; // Lanjut ke proses berikutnya
}

// =========================================================================
// Helper 1B : handle_read_body_state untuk membaca header body 
// =========================================================================
int handle_read_body_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls) {
    size_t header_len = (char*)session->req.body_data - session->buffer;
    session->req.body_length = session->buf_len - header_len;

    while (session->req.body_length < (size_t)session->req.content_length) {
        if (session->buf_len >= session->buf_capacity - 1) {
            size_t new_cap = session->buf_capacity * 2;
            char *new_buf = realloc(session->buffer, new_cap);
            if (!new_buf) return -1;

            if (new_buf != session->buffer) {
                ptrdiff_t diff = new_buf - session->buffer;
                if (session->req.uri)          session->req.uri += diff;
                if (session->req.directory)    session->req.directory += diff;
                if (session->req.query_string) session->req.query_string += diff;
                if (session->req.host)         session->req.host += diff;
                if (session->req.content_type) session->req.content_type += diff;
                if (session->req.cookie_data)  session->req.cookie_data += diff;
                if (session->req.body_data)    session->req.body_data = (void*)((char*)session->req.body_data + diff);
                if (session->req.path_info)    session->req.path_info += diff;
            }
            session->buffer = new_buf;
            session->buf_capacity = new_cap;
        }

        size_t to_read = session->buf_capacity - session->buf_len - 1;
        ssize_t n = is_tls ? SSL_read(conn->ssl, session->buffer + session->buf_len, (int)to_read)
                           : recv(sock_client, session->buffer + session->buf_len, to_read, 0);

        if (n > 0) {
            session->buf_len += n;
            session->buffer[session->buf_len] = '\0';
            session->req.body_length = session->buf_len - header_len;
        } else if (n < 0) {
            if (is_tls) {
                int err = SSL_get_error(conn->ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 2;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 2;
            }
            return -1;
        } else {
            return 0;
        }
    }

    session->state = STATE_HANDLE_REQUEST;
    return 1;
}

// =========================================================================
// Helper 2 : Routing Bridge
// =========================================================================
int http1_manager_routing_bridge(halmos_conn_t *conn, HTTP1Session *session) {
    int sock_client = conn->fd;
    bool is_tls = (conn->ssl != NULL);

    if (session->req.is_upgrade && strcmp(session->req.uri, "/ws") == 0) {
        ws_upgrade_handshake(sock_client, &session->req);
        halmos_set_websocket_fd(sock_client, true);
        http1_parser_free_memory(&session->req);
        conn->protocol_session = NULL;
        return 1; 
    }

    int backend_type = -1;
    if (has_extension(session->req.uri, session->req.path_info, ".php")) backend_type = 0;
    else if (has_extension(session->req.uri, session->req.path_info, config.rust.ext)) backend_type = 1;
    else if (has_extension(session->req.uri, session->req.path_info, config.python.ext)) backend_type = 2;

    if (backend_type != -1) {
        FCGI_Session *fcgi_sess = fcgi_session_create(sock_client, is_tls, conn->ssl, &session->req, backend_type);
        if (!fcgi_sess) {
            write_log_error_code(ERR_PROTO_H1_FSM);
            http1_response_send_mem(sock_client, 502, "Bad Gateway", "502 Bad Gateway", false, is_tls);
            return 0;
        }

        int request_id = 1; 
        unsigned char gather_buf[65536];
        int g_ptr = 0;
        
        fcgi_proto_begin_request(gather_buf, &g_ptr, request_id);
        fcgi_proto_build_params(&session->req, sock_client, session->req.content_length, gather_buf, &g_ptr, request_id);
        
        if (session->req.content_length > 0 && session->req.body_data) {
            g_ptr += fcgi_proto_build_stdin_record(request_id, session->req.body_data, session->req.content_length, gather_buf + g_ptr, sizeof(gather_buf) - g_ptr);
        } else {
            g_ptr += fcgi_proto_build_empty_stdin_record(request_id, gather_buf + g_ptr, sizeof(gather_buf) - g_ptr);
        }

        // --- PENANGANAN PENGIRIMAN KE FPM (NON-BLOCKING TANPA usleep) ---
        ssize_t total_sent = 0;
        int retries = 0;
        while (total_sent < g_ptr) {
            ssize_t sent = send(fcgi_sess->fpm_fd, gather_buf + total_sent, g_ptr - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    retries++;
                    if (retries > 1000) {
                        //fprintf(stderr, "[ROUTING_DEBUG] ERROR: FPM send buffer full after max retries!\n");
                        break;
                    }
                    sched_yield(); // Beri giliran CPU ke thread lain tanpa menidurkan thread selama 1ms
                    continue;
                } else {
                    //fprintf(stderr, "[ROUTING_DEBUG] ERROR: send to FastCGI backend failed: %s (fd=%d)\n", 
                    //        strerror(errno), fcgi_sess->fpm_fd);
                    break;
                }
            }
            total_sent += sent;
        }

        //fprintf(stderr, "[ROUTING_DEBUG] FastCGI header/params sent: %zd of %d bytes to fpm_fd=%d\n", 
        //        total_sent, g_ptr, fcgi_sess->fpm_fd);

        session->fcgi_session_id = fcgi_sess->session_id;
        
        if (!fcgi_event_loop_add(fcgi_sess->fpm_fd, fcgi_sess, EPOLLIN)) {
            //fprintf(stderr, "[ROUTING_DEBUG] ERROR: fcgi_event_loop_add failed for fpm_fd=%d\n", fcgi_sess->fpm_fd);
        }

        session->state = STATE_FCGI_PROCESSING;
        return 2; // Kembali ke EPOLLIN untuk menunggu balasan FSM
    }

    VHostEntry *vh = (VHostEntry *)session->req.vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
    char *safe_path = sanitize_path(active_root, session->req.uri);
    struct stat st;

    if (!safe_path || stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (safe_path) free(safe_path);
        write_log_access("HTTP/1.1", session->req.client_ip, session->req.method, session->req.uri, 404, 21);
        http1_response_send_mem(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", false, is_tls);
        return 0;
    }

    session->file_fd = open(safe_path, O_RDONLY);
    free(safe_path);
    if (session->file_fd == -1) return 0;

    session->file_remaining = st.st_size;
    session->file_offset = 0;
    
    session->header_len = snprintf(session->header_buf, sizeof(session->header_buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: Halmos/1.0.0\r\n"
        "Connection: %s\r\n\r\n",
        get_mime_type(session->req.uri), (long)st.st_size, session->req.is_keep_alive ? "keep-alive" : "close");
    
    session->header_sent_offset = 0;
    session->is_header_sent = false;

    session->state = STATE_SEND_STATIC_FILE;
    return 3;
}

// =========================================================================
// Helper 3: Menangani State Pemrosesan & Pengiriman FastCGI (Kembali ke Stabil)
// =========================================================================
int handle_fcgi_processing_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls) {
    // Redam warning unused parameter
    (void)conn;
    (void)sock_client;
    (void)is_tls;

    FCGI_Session *fs = fcgi_session_slot_get(session->fcgi_session_id);

    if (fs == NULL || fs->state == FCGI_SESSION_FREE || !fs->is_fcgi_active) {
        if (fs) fcgi_session_release(fs);
        session->fcgi_session_id = -1;
        
        // Reset sesi untuk Keep-Alive berikutnya
        bool keep_alive = session->req.is_keep_alive;
        http1_parser_free_memory(&session->req);
        memset(&session->req, 0, sizeof(RequestHeader));
        session->buf_len = 0;
        if (session->buffer) session->buffer[0] = '\0';
        session->is_header_sent = false;
        session->state = STATE_READ_HEADERS;
        
        return keep_alive ? 2 : 0;
    }

    // JANGAN PANGGIL fcgi_session_release(fs) DI SINI! 
    // Biarkan slot tetap dipegang selama request aktif.
    //fcgi_session_release(fs);

    return 2; // Keep waiting (EPOLLIN dari fpm_fd)
}

// =========================================================================
// Helper 4: Menangani State Pengiriman File Statis
// =========================================================================
int handle_static_file_state(halmos_conn_t *conn, HTTP1Session *session, int sock_client, bool is_tls) {
    long total_file_size = 0;
    if (session->file_fd >= 0) {
        struct stat file_st;
        if (fstat(session->file_fd, &file_st) == 0) {
            total_file_size = file_st.st_size;
        }
    }

    int res = is_tls ? http1_response_ssl(conn, session) 
                     : http1_response_plain(sock_client, session);

    if (res == 3 || res == 2) {
        return res; 
    }

    if (res <= 0) {
        http1_parser_free_memory(&session->req);
        if (session->file_fd >= 0) {
            close(session->file_fd);
            session->file_fd = -1;
        }
        return 0; 
    }
    
    write_log_access("HTTP/1.1", session->req.client_ip, session->req.method, session->req.uri, 200, session->header_len + total_file_size);
    
    if (session->file_fd >= 0) {
        close(session->file_fd);
        session->file_fd = -1;
    }

    bool keep_alive = session->req.is_keep_alive;
    http1_parser_free_memory(&session->req);
    memset(&session->req, 0, sizeof(RequestHeader));
    
    session->buf_len = 0;
    if (session->buffer) session->buffer[0] = '\0';
    session->state = STATE_READ_HEADERS;
    
    return keep_alive ? 2 : 0;
}
