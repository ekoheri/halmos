#include "halmos_http2_router.h"
#include "halmos_global.h"
#include "halmos_http2_stream.h" // Jika membutuhkan fungsi helper stream
#include "halmos_http2_response.h"
#include "halmos_http2_frame.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi.h"
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

            http2_response_send_complex_header(session, stream, raw_headers, 0x04);
            http2_response_send_data(session, stream, (unsigned char*)body_data, body_len, true);
        } else {
            http2_response_send_complex_header(session, stream, backend_data, 0x05);
            http2_response_send_data(session, stream, NULL, 0, true);
        }
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 200, body_len);
        free(backend_data);
    } else {
        http2_response_send_header(session, stream, 502);
        http2_response_send_data(session, stream, "Bad Gateway", 11, true);
        write_log_access("HTTP/2", req->client_ip, req->method, req->uri, 502, 11);
    }
    stream->state = 4;
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