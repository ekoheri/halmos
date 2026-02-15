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

//static ssize_t halmos_recv(int fd, void *buf, size_t len);

// Helper internal untuk menambahkan pasangan Params (Key-Value)
int add_fcgi_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    int name_len = (int)strlen(name);
    const char* val_ptr = value ? value : "";
    int value_len = (int)strlen(val_ptr);

    if (offset + name_len + value_len + 8 > max_len) return 0;

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

// Fungsi Utama Marshalling: Merakit semua Header CGI
int halmos_fcgi_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id) {
    int fpm_sock = halmos_fcgi_conn_acquire(target, port);
    if (fpm_sock == -1) {
        return -1;
    }

    // 1. BEGIN REQUEST
    HalmosFCGI_Header *h = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(h, 0, sizeof(HalmosFCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id;
    h->contentLengthB0 = 8;
    *g_ptr += sizeof(HalmosFCGI_Header);
    
    gather_buf[(*g_ptr)++] = 0; // Role Responder B1
    gather_buf[(*g_ptr)++] = FCGI_RESPONDER; // Role Responder B0
    gather_buf[(*g_ptr)++] = FCGI_KEEP_CONN; // Keep Conn Flag
    memset(&gather_buf[*g_ptr], 0, 5); // Reserved
    *g_ptr += 5;

    return fpm_sock;
}

void halmos_fcgi_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id) {
    #define FCGI_ADD_PARAM(buf, key, val, offset) \
    do { \
        const char *v__ = (const char *)(val); \
        if (v__ && v__[0] != '\0') { \
            offset = add_fcgi_pair(buf, key, v__, offset, 16384); \
        } \
    } while (0)

    int params_start = *g_ptr + sizeof(HalmosFCGI_Header);
    int p_offset = params_start;

    char full_script_path[1024];
    char script_name_only[512] = {0};
    const char *active_root = get_active_root(req->host);

    //size_t script_len = strlen(req->directory);
    //if (req->path_info && req->path_info[0] != '\0') {
    //    script_len = req->path_info - req->directory;
    //}

    // --- PERBAIKAN START ---
    if (!req->directory) {
        write_log_error("[FCGI] Error: Directory pointer is NULL");
        return; 
    }

    size_t full_dir_len = strlen(req->directory);
    size_t script_len = full_dir_len;

    // Pastikan path_info valid dan berada di dalam rentang memori yang sama
    if (req->path_info && req->path_info >= req->directory && req->path_info < (req->directory + full_dir_len)) {
        script_len = (size_t)(req->path_info - req->directory);
    }
    // --- PERBAIKAN END --

    // DEBUG POINTER: Mari kita pelototin alamat memorinya
    /*
    fprintf(stderr, "[DEBUG-MEM-CHECK] Base Buffer (Directory): %p\n", (void*)req->directory);
    if (req->path_info) {
        fprintf(stderr, "[DEBUG-MEM-CHECK] Path Info: %p (Diff: %td)\n", 
                (void*)req->path_info, req->path_info - req->directory);
    }
    if (req->host) {
        fprintf(stderr, "[DEBUG-MEM-CHECK] Host: %p (Diff: %td)\n", 
                (void*)req->host, req->host - req->directory);
    }
    */

    if (script_len < sizeof(script_name_only)) {
        strncpy(script_name_only, req->directory, script_len);
        script_name_only[script_len] = '\0';
    }

    if (active_root[strlen(active_root)-1] == '/' && script_name_only[0] == '/') {
        snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, script_name_only + 1);
    } else {
        snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, script_name_only);
    }
    
    /*
    fprintf(stderr, "\n--- CEK DATA REQUEST (FD: %d) ---\n", sock_client);
    fprintf(stderr, "URI Asli (req->uri): %s\n", req->uri ? req->uri : "NULL");
    fprintf(stderr, "Directory: %s\n", req->directory ? req->directory : "NULL");
    fprintf(stderr, "Query String: %s\n", req->query_string ? req->query_string : "NULL");
    fprintf(stderr, "---------------------------------\n");

    fprintf(stderr, "[DEBUG-PARAMS] URI: %s | QS: %s\n", 
        req->directory ? req->directory : "NULL", 
        req->query_string ? req->query_string : "EMPTY/NULL");
    */

    FCGI_ADD_PARAM(gather_buf, "DOCUMENT_ROOT",   active_root, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SCRIPT_FILENAME", full_script_path, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SCRIPT_NAME",      script_name_only, p_offset);
    FCGI_ADD_PARAM(gather_buf, "REQUEST_URI",      req->directory, p_offset);
    if (req->path_info && req->path_info[0] != '\0') {
        FCGI_ADD_PARAM(gather_buf, "PATH_INFO", req->path_info, p_offset);
    }
    FCGI_ADD_PARAM(gather_buf, "REQUEST_METHOD",  req->method, p_offset);
    FCGI_ADD_PARAM(gather_buf, "QUERY_STRING",    req->query_string ? req->query_string : "", p_offset);
    FCGI_ADD_PARAM(gather_buf, "HTTP_COOKIE",     req->cookie_data ? req->cookie_data : "", p_offset);

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    char remote_addr[INET_ADDRSTRLEN] = "127.0.0.1";
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_size) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, remote_addr, INET_ADDRSTRLEN);
    }
    FCGI_ADD_PARAM(gather_buf, "REMOTE_ADDR",     remote_addr, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SERVER_NAME",     config.server_name, p_offset);
    
    char s_port_str[10];
    snprintf(s_port_str, sizeof(s_port_str), "%d", config.server_port);
    FCGI_ADD_PARAM(gather_buf, "SERVER_PORT",     s_port_str, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SERVER_PROTOCOL", "HTTP/1.1", p_offset);
    FCGI_ADD_PARAM(gather_buf, "GATEWAY_INTERFACE", "CGI/1.1", p_offset);
    
    char cl_str[20];
    if (content_length > 0) {
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM(gather_buf, "CONTENT_LENGTH", cl_str, p_offset);
        const char *ct = req->content_type;
        if (ct) {
            while (*ct == ' ' || *ct == '\t') ct++;
        }
        if (!ct || strlen(ct) == 0) {
            ct = "application/x-www-form-urlencoded";
        }
        FCGI_ADD_PARAM(gather_buf, "CONTENT_TYPE", (ct && *ct) ? ct : "application/x-www-form-urlencoded", p_offset);
    } else {
        FCGI_ADD_PARAM(gather_buf, "CONTENT_LENGTH", "0", p_offset);
    }

    int p_len = p_offset - params_start;
    #undef FCGI_ADD_PARAM

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

    HalmosFCGI_Header *peh = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(peh, 0, sizeof(HalmosFCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF;
    peh->requestIdB0 = request_id & 0xFF;
    *g_ptr += sizeof(HalmosFCGI_Header);
}

// UPDATE: Hapus parameter post_data_len karena tidak dipakai
int halmos_fcgi_send_and_receive(int fpm_sock, int sock_client, RequestHeader *req, int request_id, unsigned char *gather_buf, int g_ptr, void *post_data, size_t content_length) {
    // 1. Kirim Header-header FastCGI
    if (send(fpm_sock, gather_buf, g_ptr, 0) < 0) {
        halmos_fcgi_conn_release(fpm_sock);
        return -1;
    }

    // 2. Kirim Body (Pakai content_length langsung)
    if (content_length > 0 && post_data != NULL) {
        halmos_fcgi_send_stdin(fpm_sock, request_id, post_data, (int)content_length);
    }

    // 3. Kirim paket penutup STDIN
    halmos_fcgi_send_stdin(fpm_sock, request_id, NULL, 0);

    // 4. Baca Response dari PHP
    int status = halmos_fcgi_splice_response(fpm_sock, sock_client, req);
    
    if (status != 0) {
        write_log_error("[FCGI] Protocol error or backend hangup for URI: %s", req->uri);
    }
    
    if (req && !req->is_keep_alive && !config.tls_enabled) {
        shutdown(sock_client, SHUT_RDWR);
        close(sock_client);
    }

    halmos_fcgi_conn_release(fpm_sock);
    return status;
}

void halmos_fcgi_send_stdin(int sockfd, int request_id, const void *data, int data_len) {
    int sent_so_far = 0;
    
    if (data_len > 0 && data != NULL) {
        while (sent_so_far < data_len) {
            int chunk_size = (data_len - sent_so_far > 65535) ? 65535 : (data_len - sent_so_far);
            int padding_len = (8 - (chunk_size % 8)) % 8;
            unsigned char padding[8] = {0};

            HalmosFCGI_Header header; // Pakai struct lo sendiri
            memset(&header, 0, sizeof(header));
            header.version = FCGI_VERSION_1;
            header.type = FCGI_STDIN;
            header.requestIdB1 = (request_id >> 8) & 0xFF;
            header.requestIdB0 = request_id & 0xFF;
            header.contentLengthB1 = (chunk_size >> 8) & 0xFF;
            header.contentLengthB0 = chunk_size & 0xFF;
            header.paddingLength = padding_len;

            // Kumpulkan 3 bagian data dalam satu iovec
            struct iovec iov[3];
            iov[0].iov_base = &header;
            iov[0].iov_len  = 8;
            iov[1].iov_base = (char*)data + sent_so_far;
            iov[1].iov_len  = chunk_size;
            iov[2].iov_base = padding;
            iov[2].iov_len  = padding_len;

            // Kirim sekaligus (Atomic)
            if (writev(sockfd, iov, 3) < 0) {
                write_log_error("[ERROR] Failed to send STDIN: %s", strerror(errno));
                break;
            }
            
            sent_so_far += chunk_size;
        }
    } else {
        // Kirim paket penutup (Empty STDIN)
        HalmosFCGI_Header empty_h = {0};
        empty_h.version = FCGI_VERSION_1;
        empty_h.type = FCGI_STDIN;
        empty_h.requestIdB0 = request_id; // Simple ID handle
        
        send(sockfd, &empty_h, 8, MSG_NOSIGNAL);
    }
}

/*
ssize_t halmos_recv(int fd, void *buf, size_t len) {
    if (config.tls_enabled) {
        SSL *ssl = get_ssl_for_fd(fd);
        return SSL_read(ssl, buf, (int)len);
    }
    return recv(fd, buf, len, 0);
}
*/