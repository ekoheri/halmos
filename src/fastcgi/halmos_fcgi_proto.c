#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_sec_traffic.h"

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#ifndef GATHER_BUF_SIZE
#define GATHER_BUF_SIZE 65536
#endif

// Helper internal untuk pasangan key-value
static int  fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len);

//static int safe_send_all(int sockfd, const void *buf, size_t len);

/* --- CORE FUNCTIONS --- */

int fcgi_proto_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id) {
    int fpm_sock = fcgi_pool_conn_acquire(target, port);
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

void fcgi_proto_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id) {
    (void)sock_client;
    
    // 1. Simpan posisi header PARAMS
    int header_pos = *g_ptr;
    *g_ptr += sizeof(HalmosFCGI_Header); // Loncat dulu agar p_offset mulai setelah header
    int p_offset = *g_ptr;

    VHostEntry *vh = http_vhost_get_context(req->host);
    const char *active_root = (vh) ? vh->root : config.document_root;
    char full_script_path[4096];
    char script_name_only[512] = {0};

    // Script & Path Logic
    size_t full_dir_len = req->directory ? strlen(req->directory) : 0;
    size_t script_len = full_dir_len;

    if (req->path_info && req->path_info >= req->directory && req->path_info < (req->directory + full_dir_len)) {
        script_len = (size_t)(req->path_info - req->directory);
    }

    if (script_len < sizeof(script_name_only)) {
        memcpy(script_name_only, req->directory, script_len);
        script_name_only[script_len] = '\0';
    }

    snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, 
            (active_root[strlen(active_root)-1] == '/' && script_name_only[0] == '/') ? script_name_only + 1 : script_name_only);

    // Macro yang sedikit lebih galak (kasih log kalau NULL)
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
    FCGI_ADD_PARAM_SAFE("REQUEST_URI",     req->uri);
    FCGI_ADD_PARAM_SAFE("REQUEST_METHOD",  req->method);
    FCGI_ADD_PARAM_SAFE("QUERY_STRING",    req->query_string ? req->query_string : "");
    FCGI_ADD_PARAM_SAFE("PATH_INFO",       req->path_info ? req->path_info : "");
    FCGI_ADD_PARAM_SAFE("SERVER_PROTOCOL", "HTTP/1.1");
    FCGI_ADD_PARAM_SAFE("GATEWAY_INTERFACE", "CGI/1.1");
    
    // --- REMOTE ADDR (KRUSIAL: Kasih fallback!) ---
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

    // --- CONTENT HANDLING (PENYEBAB $_FILES KOSONG) ---
    if (content_length > 0) {
        char cl_str[24];
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM_SAFE("CONTENT_LENGTH", cl_str);
        
        const char *type_to_send = req->content_type;

        if (type_to_send) {
            //fprintf(stderr, "[H2-FCGI-DEBUG] CONTENT_TYPE DETECTED: %s\n", type_to_send);
        } else {
            //fprintf(stderr, "[H2-FCGI-DEBUG] CONTENT_TYPE MISSING! Falling back to urlencoded.\n");
            type_to_send = "application/x-www-form-urlencoded";
        }
        
        // Kirim yang sebenarnya dipilih
        FCGI_ADD_PARAM_SAFE("CONTENT_TYPE", type_to_send);
    }

    // 2. Finalisasi Header PARAMS
    int p_len = p_offset - *g_ptr;
    int pad = (8 - (p_len % 8)) % 8;

    HalmosFCGI_Header *ph = (HalmosFCGI_Header*)&gather_buf[header_pos];
    ph->version = FCGI_VERSION_1;
    ph->type = FCGI_PARAMS;
    ph->requestIdB1 = (request_id >> 8) & 0xFF;
    ph->requestIdB0 = request_id & 0xFF;
    ph->contentLengthB1 = (p_len >> 8) & 0xFF;
    ph->contentLengthB0 = p_len & 0xFF;
    ph->paddingLength = (unsigned char)pad;
    ph->reserved = 0;

    // Update global pointer ke posisi setelah data + padding
    *g_ptr = p_offset;
    for(int i = 0; i < pad; i++) gather_buf[(*g_ptr)++] = 0;

    // 3. Tambahkan EMPTY PARAMS (Tanda akhir params)
    HalmosFCGI_Header *peh = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(peh, 0, sizeof(HalmosFCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF;
    peh->requestIdB0 = request_id & 0xFF;
    *g_ptr += sizeof(HalmosFCGI_Header);
}

int fcgi_proto_send_and_receive(int fpm_sock, int sock_client, RequestHeader *req, int request_id, unsigned char *gather_buf, int g_ptr, void *post_data, size_t content_length) {
    int status = 0;

    /*
    fprintf(stderr, "\n[DEBUG-FLOW] === START FCGI SEND AND RECEIVE ===\n");
    fprintf(stderr, "[DEBUG-FLOW] Request ID: %d, Content-Len: %zu\n", request_id, content_length);
    fprintf(stderr, "[DEBUG-FLOW] Post Data Pointer: %p\n", post_data);
    fprintf(stderr, "[DEBUG-FLOW] Gather Buffer (Header) Size: %d\n", g_ptr);
    */

    if (safe_send_all(fpm_sock, gather_buf, g_ptr) < 0) {
        //fprintf(stderr, "[DEBUG-FLOW] Gagal kirim Header PARAMS\n");
        status = -1;
        goto cleanup;
    }

    // Panggil kirim STDIN
    fcgi_proto_send_stdin(fpm_sock, request_id, post_data, (int)content_length);

    //fprintf(stderr, "[DEBUG-FLOW] Menunggu respon dari PHP-FPM...\n");
    status = fcgi_io_splice_response(fpm_sock, sock_client, req);
    //fprintf(stderr, "[DEBUG-FLOW] === END FCGI SEND AND RECEIVE (Status: %d) ===\n\n", status);
    
cleanup:
    fcgi_pool_conn_release(fpm_sock);
    return status;    
}

void fcgi_proto_send_stdin(int sockfd, int request_id, const void *data, int data_len) {
    //fprintf(stderr, "[TRACE-STDIN] Masuk ke fcgi_proto_send_stdin\n");
    //fprintf(stderr, "[TRACE-STDIN] ReqID: %d | DataAddr: %p | Len: %d\n", request_id, data, data_len);

    if (data_len > 0 && data != NULL) {
        int sent_payload = 0;
        while (sent_payload < data_len) {
            int chunk = (data_len - sent_payload > 32768) ? 32768 : (data_len - sent_payload);
            int pad = (8 - (chunk % 8)) % 8;
            
            unsigned char record_buf[sizeof(HalmosFCGI_Header) + 32768 + 8]; 
            int r_ptr = 0;

            HalmosFCGI_Header *h = (HalmosFCGI_Header*)record_buf;
            h->version = FCGI_VERSION_1;
            h->type = FCGI_STDIN;
            h->requestIdB1 = (request_id >> 8) & 0xFF;
            h->requestIdB0 = request_id & 0xFF;
            h->contentLengthB1 = (chunk >> 8) & 0xFF;
            h->contentLengthB0 = chunk & 0xFF;
            h->paddingLength = (unsigned char)pad;
            h->reserved = 0;
            r_ptr += sizeof(HalmosFCGI_Header);

            memcpy(record_buf + r_ptr, (char*)data + sent_payload, chunk);
            r_ptr += chunk;
            
            if (pad > 0) {
                memset(record_buf + r_ptr, 0, pad);
                r_ptr += pad;
            }

            if (safe_send_all(sockfd, record_buf, r_ptr) < 0) {
                //fprintf(stderr, "[TRACE-STDIN] Error saat kirim chunk!\n");
                return;
            }
            sent_payload += chunk;
        }
        //fprintf(stderr, "[TRACE-STDIN] Berhasil kirim total payload: %d\n", sent_payload);
    }

    // Kirim Empty STDIN (EOF) - HANYA JIKA data_len >= 0
    HalmosFCGI_Header empty_h = {0};
    empty_h.version = FCGI_VERSION_1;
    empty_h.type = FCGI_STDIN;
    empty_h.requestIdB1 = (request_id >> 8) & 0xFF;
    empty_h.requestIdB0 = request_id & 0xFF;
    
    if (safe_send_all(sockfd, &empty_h, sizeof(empty_h)) >= 0) {
        //fprintf(stderr, "[TRACE-STDIN] EOF (Empty STDIN) Sent for ReqID: %d\n", request_id);
    }
}

int safe_send_all(int sockfd, const void *buf, size_t len) {
    size_t total_sent = 0;
    const unsigned char *ptr = (const unsigned char *)buf;

    while (total_sent < len) {
        ssize_t n = send(sockfd, ptr + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (errno == EINTR) continue; // Terganggu sinyal, coba lagi
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Di sini biasanya kita pakai poll/select, 
                // tapi untuk FCGI kita asumsikan blocking mode yang aman.
                continue; 
            }
            return -1; // Error beneran (koneksi putus/SIGPIPE)
        }
        total_sent += n;
    }
    return 0;
}

/* --- INTERNAL HELPER --- */

/**
 * Menambahkan pasangan Key-Value ke buffer FastCGI sesuai spesifikasi.
 * Mendukung format 1-byte length (< 128) dan 4-byte length (>= 128).
 */
int fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    if (!name) return offset;

    size_t name_len = strlen(name);
    const char* val_ptr = value ? value : "";
    size_t value_len = strlen(val_ptr);

    // 1. Hitung berapa byte yang dibutuhkan untuk menyimpan informasi panjang (length)
    // Spesifikasi FastCGI: Jika length > 127, gunakan 4 byte (bit paling kiri diset 1)
    int h_name = (name_len > 127) ? 4 : 1;
    int h_val  = (value_len > 127) ? 4 : 1;
    
    // 2. Cek apakah buffer cukup sebelum menulis
    if (offset + h_name + h_val + (int)name_len + (int)value_len > max_len) {
        //fprintf(stderr, "[FCGI-ERR] Buffer overflow saat menambah param: %s\n", name);
        return offset; 
    }

    // 3. Tulis Panjang Nama (Name Length)
    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)name_len;
    }

    // 4. Tulis Panjang Nilai (Value Length)
    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)value_len;
    }

    // 5. Tulis Data Nama
    memcpy(dest + offset, name, name_len);
    offset += name_len;

    // 6. Tulis Data Nilai
    memcpy(dest + offset, val_ptr, value_len);
    offset += value_len;
    
    return offset;
}

