#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_http1_header.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define GATHER_BUF_SIZE 65536

// Helper internal untuk menambahkan pasangan key-value FastCGI
static int fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len);

/* --- PROTOCOL BUILDER FUNCTIONS (STATELESS) --- */

int fcgi_proto_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id) {
    // Membuka socket TCP ke PHP-FPM upstream
    struct sockaddr_in serv_addr;
    int fpm_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fpm_sock < 0) return -1;

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, target, &serv_addr.sin_addr) <= 0) {
        close(fpm_sock);
        return -1;
    }

    if (connect(fpm_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(fpm_sock);
        return -1;
    }

    // --- TAMBAHKAN KODE INI AGAR SOCKET NON-BLOCKING UNTUK EPOLL ---
    int flags = fcntl(fpm_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fpm_sock, F_SETFL, flags | O_NONBLOCK);
    }
    // -------------------------------------------------------------

    FCGI_Header *h = (FCGI_Header*)&gather_buf[*g_ptr];
    memset(h, 0, sizeof(FCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id & 0xFF;
    h->requestIdB1 = (request_id >> 8) & 0xFF;
    h->contentLengthB0 = 8;
    *g_ptr += sizeof(FCGI_Header);
    
    gather_buf[(*g_ptr)++] = 0; // Role Responder B1
    gather_buf[(*g_ptr)++] = 1; // Role Responder B0 (FCGI_RESPONDER = 1)
    gather_buf[(*g_ptr)++] = FCGI_KEEP_CONN; // Keep Conn Flag
    memset(&gather_buf[*g_ptr], 0, 5); 
    *g_ptr += 5;

    return fpm_sock; // Sekarang socket sudah non-blocking dan aman untuk epoll!
}

void fcgi_proto_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id) {
    (void)sock_client;
    
    // 1. Simpan posisi header PARAMS
    int header_pos = *g_ptr;
    *g_ptr += sizeof(FCGI_Header); // Loncat dulu agar p_offset mulai setelah header
    int p_offset = *g_ptr;

    VHostEntry *vh = http_vhost_get_context(req->host);
    const char *active_root = (vh) ? vh->root : config.document_root;
    char full_script_path[4096];
    char script_name_only[512] = {0};

    // Script & Path Logic
    const char *raw_uri = req->uri ? req->uri : "/";
    snprintf(script_name_only, sizeof(script_name_only), "%s", raw_uri);

    char *qmark = strchr(script_name_only, '?');
    if (qmark) {
        *qmark = '\0';
    }

    if (req->path_info && strlen(req->path_info) > 0) {
        char *pinfo_pos = strstr(script_name_only, req->path_info);
        if (pinfo_pos && pinfo_pos > script_name_only) {
            *pinfo_pos = '\0';
        }
    }

    snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, 
            (active_root[strlen(active_root)-1] == '/' && script_name_only[0] == '/') ? script_name_only + 1 : script_name_only);

    #define FCGI_ADD_PARAM_SAFE(key, val) do { \
        const char *v__ = (const char *)(val); \
        if (v__) { \
            p_offset = fcgi_proto_add_pair(gather_buf, key, v__, p_offset, GATHER_BUF_SIZE); \
        } \
    } while (0)

    // --- MANDATORY CGI PARAMS ---
    FCGI_ADD_PARAM_SAFE("DOCUMENT_ROOT",   active_root);
    FCGI_ADD_PARAM_SAFE("SCRIPT_FILENAME", full_script_path);
    FCGI_ADD_PARAM_SAFE("SCRIPT_NAME",     script_name_only);
    FCGI_ADD_PARAM_SAFE("PHP_SELF",        script_name_only);
    FCGI_ADD_PARAM_SAFE("REQUEST_URI",     req->uri);
    FCGI_ADD_PARAM_SAFE("REQUEST_METHOD",  req->method);
    FCGI_ADD_PARAM_SAFE("QUERY_STRING",    req->query_string ? req->query_string : "");
    FCGI_ADD_PARAM_SAFE("PATH_INFO",       req->path_info ? req->path_info : "");
    FCGI_ADD_PARAM_SAFE("SERVER_PROTOCOL", "HTTP/1.1");
    FCGI_ADD_PARAM_SAFE("GATEWAY_INTERFACE", "CGI/1.1");
    
    // --- REMOTE ADDR & SERVER INFO ---
    FCGI_ADD_PARAM_SAFE("REMOTE_ADDR",     req->client_ip ? req->client_ip : "127.0.0.1");
    FCGI_ADD_PARAM_SAFE("SERVER_NAME",     req->host ? req->host : config.server_name);
    
    // --- TLS DETECTION ---
    if (req->is_tls) {
        FCGI_ADD_PARAM_SAFE("HTTPS", "on");
        FCGI_ADD_PARAM_SAFE("REQUEST_SCHEME", "https");
    } else {
        FCGI_ADD_PARAM_SAFE("REQUEST_SCHEME", "http");
    }

    char s_port_str[10];
    snprintf(s_port_str, sizeof(s_port_str), "%d", config.server_port);
    FCGI_ADD_PARAM_SAFE("SERVER_PORT", s_port_str);
    
    if (req->cookie_data) FCGI_ADD_PARAM_SAFE("HTTP_COOKIE", req->cookie_data);

    // --- CONTENT HANDLING ---
    if (content_length > 0) {
        char cl_str[24];
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM_SAFE("CONTENT_LENGTH", cl_str);
        
        const char *type_to_send = req->content_type;
        if (!type_to_send) {
            type_to_send = "application/x-www-form-urlencoded";
        }
        FCGI_ADD_PARAM_SAFE("CONTENT_TYPE", type_to_send);
    }

    // 2. Finalisasi Header PARAMS
    // Perhitungan panjang payload (p_len) adalah selisih antara posisi p_offset saat ini 
    // dikurangi posisi awal data (setelah header_pos + sizeof(FCGI_Header))
    int p_len = p_offset - (header_pos + (int)sizeof(FCGI_Header));
    int pad = (8 - (p_len % 8)) % 8;

    FCGI_Header *ph = (FCGI_Header*)&gather_buf[header_pos];
    ph->version = FCGI_VERSION_1;
    ph->type = FCGI_PARAMS;
    ph->requestIdB1 = (request_id >> 8) & 0xFF;
    ph->requestIdB0 = request_id & 0xFF;
    ph->contentLengthB1 = (p_len >> 8) & 0xFF;
    ph->contentLengthB0 = p_len & 0xFF;
    ph->paddingLength = (unsigned char)pad;
    ph->reserved = 0;

    // Update global pointer ke posisi setelah data parameter
    *g_ptr = p_offset;
    
    // Tambahkan padding jika ada
    for(int i = 0; i < pad; i++) {
        gather_buf[(*g_ptr)++] = 0;
    }

    // 3. Tambahkan EMPTY PARAMS (Tanda akhir params: contentLength = 0)
    FCGI_Header *peh = (FCGI_Header*)&gather_buf[*g_ptr];
    memset(peh, 0, sizeof(FCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF;
    peh->requestIdB0 = request_id & 0xFF;
    *g_ptr += sizeof(FCGI_Header);
}

size_t fcgi_proto_build_stdin_record(int request_id, const void *data, size_t data_len, unsigned char *out_buf, size_t max_out_len) {
    size_t required_size = sizeof(FCGI_Header) + data_len;
    int pad = (8 - (data_len % 8)) % 8;
    required_size += pad;

    if (required_size > max_out_len) return 0;

    FCGI_Header *h = (FCGI_Header*)out_buf;
    h->version = FCGI_VERSION_1;
    h->type = FCGI_STDIN;
    h->requestIdB1 = (request_id >> 8) & 0xFF;
    h->requestIdB0 = request_id & 0xFF;
    h->contentLengthB1 = (data_len >> 8) & 0xFF;
    h->contentLengthB0 = data_len & 0xFF;
    h->paddingLength = (unsigned char)pad;
    h->reserved = 0;

    size_t written = sizeof(FCGI_Header);
    if (data_len > 0 && data != NULL) {
        memcpy(out_buf + written, data, data_len);
        written += data_len;
    }

    if (pad > 0) {
        memset(out_buf + written, 0, pad);
        written += pad;
    }

    return written;
}

size_t fcgi_proto_build_empty_stdin_record(int request_id, unsigned char *out_buf, size_t max_out_len) {
    if (sizeof(FCGI_Header) > max_out_len) return 0;

    FCGI_Header *empty_h = (FCGI_Header*)out_buf;
    memset(empty_h, 0, sizeof(FCGI_Header));
    empty_h->version = FCGI_VERSION_1;
    empty_h->type = FCGI_STDIN;
    empty_h->requestIdB1 = (request_id >> 8) & 0xFF;
    empty_h->requestIdB0 = request_id & 0xFF;

    return sizeof(FCGI_Header);
}

/* --- INTERNAL HELPER --- */

int fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    if (!name) return offset;

    size_t name_len = strlen(name);
    const char* val_ptr = value ? value : "";
    size_t value_len = strlen(val_ptr);

    int h_name = (name_len > 127) ? 4 : 1;
    int h_val  = (value_len > 127) ? 4 : 1;
    
    if (offset + h_name + h_val + (int)name_len + (int)value_len > max_len) {
        return offset; 
    }

    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)name_len;
    }

    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)value_len;
    }

    memcpy(dest + offset, name, name_len);
    offset += name_len;

    memcpy(dest + offset, val_ptr, value_len);
    offset += value_len;
    
    return offset;
}