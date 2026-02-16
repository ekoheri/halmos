#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_security.h"

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

/* --- INTERNAL HELPER --- */

int add_fcgi_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    int name_len = (int)strlen(name);
    const char* val_ptr = value ? value : "";
    int value_len = (int)strlen(val_ptr);

    if (offset + name_len + value_len + 8 > max_len) return offset;

    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else dest[offset++] = (unsigned char)name_len;

    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else dest[offset++] = (unsigned char)value_len;

    memcpy(dest + offset, name, name_len);
    offset += name_len;
    memcpy(dest + offset, val_ptr, value_len);
    return offset + value_len;
}

/* --- CORE FUNCTIONS --- */

int halmos_fcgi_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id) {
    int fpm_sock = halmos_fcgi_conn_acquire(target, port);
    if (fpm_sock == -1) return -1;

    HalmosFCGI_Header *h = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(h, 0, sizeof(HalmosFCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id & 0xFF;
    h->requestIdB1 = (request_id >> 8) & 0xFF;
    h->contentLengthB0 = 8;
    *g_ptr += sizeof(HalmosFCGI_Header);
    
    gather_buf[(*g_ptr)++] = 0; // Role Responder B1
    gather_buf[(*g_ptr)++] = FCGI_RESPONDER; // Role Responder B0
    gather_buf[(*g_ptr)++] = FCGI_KEEP_CONN; // Keep Conn Flag
    memset(&gather_buf[*g_ptr], 0, 5); 
    *g_ptr += 5;

    return fpm_sock;
}

void halmos_fcgi_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id) {
    (void)sock_client;
    #define FCGI_ADD_PARAM(buf, key, val, offset) \
    do { \
        const char *v__ = (const char *)(val); \
        if (v__) { \
            offset = add_fcgi_pair(buf, key, v__, offset, 16384); \
        } \
    } while (0)

    int params_start = *g_ptr + sizeof(HalmosFCGI_Header);
    int p_offset = params_start;

    const char *active_root = get_active_root(req->host);
    char full_script_path[1024];
    char script_name_only[512] = {0};

    // Script & Path Logic
    size_t full_dir_len = req->directory ? strlen(req->directory) : 0;
    size_t script_len = full_dir_len;

    if (req->path_info && req->path_info >= req->directory && req->path_info < (req->directory + full_dir_len)) {
        script_len = (size_t)(req->path_info - req->directory);
    }

    if (script_len < sizeof(script_name_only)) {
        strncpy(script_name_only, req->directory, script_len);
        script_name_only[script_len] = '\0';
    }

    snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, 
            (active_root[strlen(active_root)-1] == '/' && script_name_only[0] == '/') ? script_name_only + 1 : script_name_only);

    // --- MANDATORY CGI PARAMS ---
    FCGI_ADD_PARAM(gather_buf, "DOCUMENT_ROOT",   active_root, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SCRIPT_FILENAME", full_script_path, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SCRIPT_NAME",      script_name_only, p_offset);
    FCGI_ADD_PARAM(gather_buf, "REQUEST_URI",      req->uri, p_offset);
    FCGI_ADD_PARAM(gather_buf, "REQUEST_METHOD",  req->method, p_offset);
    FCGI_ADD_PARAM(gather_buf, "QUERY_STRING",    req->query_string ? req->query_string : "", p_offset);
    FCGI_ADD_PARAM(gather_buf, "PATH_INFO",    req->path_info ? req->path_info : "", p_offset);
    FCGI_ADD_PARAM(gather_buf, "SERVER_PROTOCOL", "HTTP/1.1", p_offset);
    FCGI_ADD_PARAM(gather_buf, "GATEWAY_INTERFACE", "CGI/1.1", p_offset);
    
    // --- TLS DETECTION (PENTING BUAT BOSS) ---
    if (req->is_tls) {
        FCGI_ADD_PARAM(gather_buf, "HTTPS", "on", p_offset);
        FCGI_ADD_PARAM(gather_buf, "REQUEST_SCHEME", "https", p_offset);
    } else {
        FCGI_ADD_PARAM(gather_buf, "REQUEST_SCHEME", "http", p_offset);
    }

    // --- REMOTE & SERVER INFO ---
    FCGI_ADD_PARAM(gather_buf, "REMOTE_ADDR",     req->client_ip, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SERVER_NAME",     req->host ? req->host : config.server_name, p_offset);
    
    char s_port_str[10];
    snprintf(s_port_str, sizeof(s_port_str), "%d", config.server_port);
    FCGI_ADD_PARAM(gather_buf, "SERVER_PORT",     s_port_str, p_offset);
    
    if (req->cookie_data) FCGI_ADD_PARAM(gather_buf, "HTTP_COOKIE", req->cookie_data, p_offset);

    // Content Handling
    if (content_length > 0) {
        char cl_str[20];
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM(gather_buf, "CONTENT_LENGTH", cl_str, p_offset);
        FCGI_ADD_PARAM(gather_buf, "CONTENT_TYPE", req->content_type ? req->content_type : "application/x-www-form-urlencoded", p_offset);
    }

    // Header Params Finalizing
    int p_len = p_offset - params_start;
    HalmosFCGI_Header *ph = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    ph->version = FCGI_VERSION_1;
    ph->type = FCGI_PARAMS;
    ph->requestIdB1 = (request_id >> 8) & 0xFF;
    ph->requestIdB0 = request_id & 0xFF;
    ph->contentLengthB1 = (p_len >> 8) & 0xFF;
    ph->contentLengthB0 = p_len & 0xFF;
    ph->paddingLength = (8 - (p_len % 8)) % 8;
    
    *g_ptr = p_offset;
    for(int i=0; i<ph->paddingLength; i++) gather_buf[(*g_ptr)++] = 0;

    // Empty Params (End of Params)
    HalmosFCGI_Header *peh = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(peh, 0, sizeof(HalmosFCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF;
    peh->requestIdB0 = request_id & 0xFF;
    *g_ptr += sizeof(HalmosFCGI_Header);
}

int halmos_fcgi_send_and_receive(int fpm_sock, int sock_client, RequestHeader *req, int request_id, unsigned char *gather_buf, int g_ptr, void *post_data, size_t content_length) {
    // 1. Kirim Semua Header Params ke PHP-FPM
    if (send(fpm_sock, gather_buf, g_ptr, 0) < 0) {
        halmos_fcgi_conn_release(fpm_sock);
        return -1;
    }

    // 2. Kirim Body (STDIN)
    if (content_length > 0 && post_data != NULL) {
        halmos_fcgi_send_stdin(fpm_sock, request_id, post_data, (int)content_length);
    }
    halmos_fcgi_send_stdin(fpm_sock, request_id, NULL, 0); // End of STDIN

    // 3. Baca & Teruskan Response (Splice)
    // Di sini req->is_tls akan menentukan apakah kirim ke client pakai SSL_write atau send
    int status = halmos_fcgi_splice_response(fpm_sock, sock_client, req);
    
    if (status != 0) {
        write_log_error("[FCGI] Backend error for URI: %s", req->uri);
    }
    
    halmos_fcgi_conn_release(fpm_sock);
    return status;
}

void halmos_fcgi_send_stdin(int sockfd, int request_id, const void *data, int data_len) {
    if (data_len > 0 && data != NULL) {
        int sent = 0;
        while (sent < data_len) {
            int chunk = (data_len - sent > 32768) ? 32768 : (data_len - sent);
            int pad = (8 - (chunk % 8)) % 8;
            unsigned char padding[8] = {0};

            HalmosFCGI_Header h = {0};
            h.version = FCGI_VERSION_1;
            h.type = FCGI_STDIN;
            h.requestIdB1 = (request_id >> 8) & 0xFF;
            h.requestIdB0 = request_id & 0xFF;
            h.contentLengthB1 = (chunk >> 8) & 0xFF;
            h.contentLengthB0 = chunk & 0xFF;
            h.paddingLength = pad;

            struct iovec iov[3] = {
                {&h, 8},
                {(char*)data + sent, chunk},
                {padding, pad}
            };
            if (writev(sockfd, iov, 3) < 0) break;
            sent += chunk;
        }
    } else {
        HalmosFCGI_Header empty_h = {0};
        empty_h.version = FCGI_VERSION_1;
        empty_h.type = FCGI_STDIN;
        empty_h.requestIdB1 = (request_id >> 8) & 0xFF;
        empty_h.requestIdB0 = request_id & 0xFF;
        send(sockfd, &empty_h, 8, MSG_NOSIGNAL);
    }
}