#include "halmos_http2_router.h"
#include "halmos_global.h"
#include "halmos_http2_stream.h" // Jika membutuhkan fungsi helper stream
#include "halmos_http2_response.h"
#include "halmos_http2_frame.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi_proto.h"
#include "halmos_fcgi_poller.h"
#include "halmos_fcgi_session.h"
#include "halmos_http_multipart.h"

// Pustaka Standar C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Pustaka Sistem & POSIX (untuk I/O, file statis, socket backend)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sys/epoll.h>

/* Helper http2_response_routing_bridge */
static void route_websocket_upgrade(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req);
static void route_fastcgi_backend(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req, int backend_type);
static void route_static_file(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req);

// Paket fungsi http2_router_bridge
void http2_router_bridge(HTTP2Session *session, HTTP2Stream *stream) {
    RequestHeader *req = &stream->http1_compat;

    // 1. INTERSEPSI HANDSHAKE WEBSOCKET HTTP/2 (RFC 8441)
    if (req->is_upgrade == true) {
        route_websocket_upgrade(session, stream, req);
        return; 
    }
    
    // 2. IDENTIFIKASI BACKEND (PHP / RUST / PYTHON)
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

    // 3. JALUR FASTCGI BACKEND
    if (backend_type != -1) {
        route_fastcgi_backend(session, stream, req, backend_type);
        return;
    }

    // 4. JALUR FILE STATIS
    route_static_file(session, stream, req);
}

/* Helper fungsi routing bridge*/
void route_websocket_upgrade(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req) {
    unsigned char ws_ok_payload[1] = { 0x88 };
    pthread_mutex_lock(&session->streams_lock);
    http2_frame_send(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, ws_ok_payload, 1);
    pthread_mutex_unlock(&session->streams_lock);
    write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, 1);
}

void route_fastcgi_backend(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req, int backend_type) {
    (void)backend_type;

    int request_id = 1;

    // 1. Buat Sesi FSM Async FastCGI baru (menyesuaikan parameter HTTP/2 Session)
    HalmosFCGISession *fcgi_sess = halmos_fcgi_session_create(session->fd, session->is_tls, NULL);
    if (!fcgi_sess) {
        write_log_error_code(ERR_PROTO_H2_FCGI_ACQ, req->uri ? req->uri : "/");
        http2_response_send_header(session, stream, 502);
        http2_response_send_data(session, stream, "Bad Gateway", 11, true);
        stream->state = 4;
        return;
    }

    if (fcgi_sess) {
        fcgi_sess->is_http2 = true;                  
        fcgi_sess->http2_stream_id = stream->stream_id; 
        
        // --- TAMBAHAN SELARAS ---
        // Simpan pointer HTTP2Session (HTTP/2 connection session) dan HTTP2Stream langsung ke fcgi_sess
        fcgi_sess->h2_session = session; 
        fcgi_sess->h2_stream = stream;   // Pointer langsung ke stream terkait!
    }

    // 2. Hubungkan ke PHP-FPM menggunakan modul proto
    unsigned char gather_buf[65536];
    int g_ptr = 0;
    
    const char *fpm_target = "127.0.0.1";
    int fpm_port = 9000;

    int fpm_sock = fcgi_proto_begin_request(fpm_target, fpm_port, gather_buf, &g_ptr, request_id);
    if (fpm_sock < 0) {
        fprintf(stderr, "[H2-MANAGER_DEBUG] ERROR: fcgi_proto_begin_request failed, returned fpm_sock=%d\n", fpm_sock);
        halmos_fcgi_session_destroy(fcgi_sess);
        http2_response_send_header(session, stream, 502);
        http2_response_send_data(session, stream, "Bad Gateway", 11, true);
        stream->state = 4;
        return;
    }

    // Set socket non-blocking
    int flags = fcntl(fpm_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fpm_sock, F_SETFL, flags | O_NONBLOCK);
    }

    fcgi_sess->fpm_fd = fpm_sock;

    // 3. Bangun Environment Variables (PARAMS)
    fcgi_proto_build_params(req, session->fd, req->content_length, gather_buf, &g_ptr, request_id);

    // Kirim Header PARAMS terlebih dahulu ke PHP-FPM
    ssize_t total_sent = 0;
    while (total_sent < g_ptr) {
        ssize_t sent = send(fpm_sock, gather_buf + total_sent, (size_t)(g_ptr - total_sent), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            } else {
                fprintf(stderr, "[H2-MANAGER_DEBUG] ERROR: send PARAMS to PHP-FPM failed: %s\n", strerror(errno));
                break;
            }
        }
        total_sent += sent;
    }

    // 4. Bangun & Kirim STDIN (Body / Upload Multipart) Secara Chunking
    if (req->content_length > 0 && req->body_data) {
        size_t sent_payload = 0;
        size_t total_len = req->content_length;
        const char *data_ptr = (const char *)req->body_data;

        while (sent_payload < total_len) {
            size_t chunk = (total_len - sent_payload > 32768) ? 32768 : (total_len - sent_payload);
            
            g_ptr = 0;
            g_ptr += fcgi_proto_build_stdin_record(request_id, data_ptr + sent_payload, chunk, gather_buf, sizeof(gather_buf));

            size_t chunk_sent = 0;
            while (chunk_sent < (size_t)g_ptr) {
                ssize_t sent = send(fpm_sock, gather_buf + chunk_sent, (size_t)g_ptr - chunk_sent, MSG_NOSIGNAL);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        usleep(1000);
                        continue;
                    }
                    fprintf(stderr, "[H2-MANAGER_DEBUG] ERROR: send STDIN chunk failed: %s\n", strerror(errno));
                    break;
                }
                chunk_sent += sent;
            }
            sent_payload += chunk;
        }
    }

    // WAJIB: Kirim Empty STDIN (EOF) sebagai penanda akhir payload ke PHP-FPM
    g_ptr = 0;
    g_ptr += fcgi_proto_build_empty_stdin_record(request_id, gather_buf, sizeof(gather_buf));
    
    size_t eof_sent = 0;
    while (eof_sent < (size_t)g_ptr) {
        ssize_t sent = send(fpm_sock, gather_buf + eof_sent, (size_t)g_ptr - eof_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            break;
        }
        eof_sent += sent;
    }

    // 5. Hubungkan stream HTTP/2 dengan sesi & fpm_fd
    pthread_mutex_lock(&session->streams_lock);
    stream->fpm_fd = fpm_sock;
    stream->is_fcgi_active = true;
    pthread_mutex_unlock(&session->streams_lock);

    // 6. Daftarkan fpm_sock ke Epoll Upstream Poller
    fprintf(stderr, "[H2-MANAGER_DEBUG] About to call poller_add with fpm_sock=%d, fcgi_sess=%p\n", fpm_sock, (void*)fcgi_sess);
    if (!halmos_fcgi_poller_add(fpm_sock, fcgi_sess, EPOLLIN)) {
        fprintf(stderr, "[H2-MANAGER_DEBUG] ERROR: halmos_fcgi_poller_add returned false for fd=%d\n", fpm_sock);
    }

    write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, 0);
}

void route_static_file(HTTP2Session *session, HTTP2Stream *stream, RequestHeader *req) {
    VHostEntry *vh = (VHostEntry *)req->vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    if (!safe_path || stat(safe_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        http2_response_send_header(session, stream, 404);
        http2_response_send_data(session, stream, "Not Found", 9, true);
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 404, 9);
        if (safe_path) free(safe_path);
        stream->state = 4;
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        http2_response_send_header(session, stream, 403);
        http2_response_send_data(session, stream, "Forbidden", 9, true);
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 403, 9);
        stream->state = 4;
    } else {
        http2_response_send_header(session, stream, 200);
        size_t file_size = (size_t)st.st_size;

        if (file_size == 0) {
            http2_response_send_data(session, stream, NULL, 0, true);
            close(fd);
            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, 0);
            stream->state = 4;
        } else {
            pthread_mutex_lock(&session->streams_lock);
            stream->file_fd = fd;
            stream->file_size = file_size;
            stream->file_offset = 0;
            stream->is_sending_file = true;
            pthread_mutex_unlock(&session->streams_lock);

            write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, file_size);
        }
    }
    if (safe_path) free(safe_path);
}
// Akhir paket fungsi http2_response_routing_bridge