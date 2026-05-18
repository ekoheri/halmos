#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>  // Wajib untuk ssize_t
#include <stddef.h>     // Untuk size_t
#include <stdint.h>

#include "halmos_fcgi.h"
#include "halmos_global.h"
#include "halmos_log.h"

#ifndef GATHER_BUF_SIZE
#define GATHER_BUF_SIZE 65536
#endif

// Fungsi bantu untuk mengubah string IP menjadi angka unik
// untuk keperluan ip_hash load balancing
static unsigned int hash_ip(const char *ip);

/**
 * fcgi_api_request_stream
 * Fungsi fasad utama yang mengatur koordinasi antar modul FCGI.
 */

/**
 * fcgi_api_request_stream
 * Fungsi fasad utama yang mengatur koordinasi antar modul FCGI.
 * Sekarang mendukung Hierarchical Backend (VHost Override).
 */
int fcgi_api_request_stream(RequestHeader *req, int sock_client, int backend_type, void *post_data, size_t content_length) {
    // 1. Siapkan pointer
    UpstreamGroup *live_group;   // Data dinamis (next_idx) di fcgi_pool
    BackendGroup  *cfg_group;    // Data statis (ips, ports) dari config/vhost
    
    // --- [TAMBAHAN LOGIKA VHOST OVERRIDE] ---
    // Cari tahu ini request untuk domain apa
    VHostEntry *vh = req->vhost_context; 

    // 2. Mapping & Seleksi Grup (VHost vs Global)
    if (backend_type == 0) { // PHP
        live_group = &fcgi_pool.php_group;
        // Gunakan VHost PHP jika node_count > 0, jika tidak pakai Global
        cfg_group  = (vh && vh->php.node_count > 0) ? &vh->php : &config.php;
    } else if (backend_type == 1) { // RUST
        live_group = &fcgi_pool.rust_group;
        cfg_group  = (vh && vh->rust.node_count > 0) ? &vh->rust : &config.rust;
    } else { // PYTHON
        live_group = &fcgi_pool.python_group;
        cfg_group  = (vh && vh->python.node_count > 0) ? &vh->python : &config.python;
    }

    // 3. Validasi: pastikan ada node yang tersedia
    if (cfg_group->node_count <= 0) {
        write_log_error("[FCGI] No nodes configured for backend type %d", backend_type);
        return -1;
    }

    /*
    [TIANG UTAMA: LOAD BALANCER]
    Idx dipilih dari cfg_group yang sudah terseleksi (bisa milik VHost atau Global).
    */
    int idx;
    if (strcmp(cfg_group->lb_strategy, "ip_hash") == 0) {
        idx = hash_ip(req->client_ip) % cfg_group->node_count;
    } else {
        // next_idx tetap global per tipe backend agar distribusi merata
        idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    }
    
    // Ambil IP dan Port spesifik dari cfg_group terpilih
    const char *selected_ip = cfg_group->ips[idx];
    int selected_port       = cfg_group->ports[idx];

    // --- LANJUT KE PROSES FCGI SEPERTI BIASA ---
    int request_id = 1;
    unsigned char gather_buf[16384];
    int g_ptr = 0;

    // 1. BEGIN REQUEST
    int fpm_sock = fcgi_proto_begin_request(selected_ip, selected_port, gather_buf, &g_ptr, request_id);
    if (fpm_sock == -1) return -1;

    // 2. BUILD PARAMS
    fcgi_proto_build_params(req, sock_client, content_length, gather_buf, &g_ptr, request_id);

    // 3. SEND & RECEIVE
    return fcgi_proto_send_and_receive(fpm_sock, sock_client, req, request_id, gather_buf, g_ptr, post_data, content_length);
}

/**
 * fcgi_api_request_http2
 * Khusus untuk HTTP/2: Tidak menulis langsung ke socket client.
 * Mengembalikan seluruh output backend (Header + Body) ke dalam *out_buf.
 */
ssize_t fcgi_api_request_http2(RequestHeader *req, int backend_type, void *post_data, size_t content_length, char **out_buf) {
    // 1. Logika Load Balancing
    VHostEntry *vh = req->vhost_context; 
    UpstreamGroup *live_group;
    BackendGroup  *cfg_group;

    if (backend_type == 0) {
        live_group = &fcgi_pool.php_group;
        cfg_group  = (vh && vh->php.node_count > 0) ? &vh->php : &config.php;
    } else if (backend_type == 1) {
        live_group = &fcgi_pool.rust_group;
        cfg_group  = (vh && vh->rust.node_count > 0) ? &vh->rust : &config.rust;
    } else {
        live_group = &fcgi_pool.python_group;
        cfg_group  = (vh && vh->python.node_count > 0) ? &vh->python : &config.python;
    }

    if (cfg_group->node_count <= 0) return -1;

    int idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    const char *selected_ip = cfg_group->ips[idx];
    int selected_port       = cfg_group->ports[idx];

    // 2. Hubungkan ke Backend
    int request_id = 1;
    unsigned char gather_buf[GATHER_BUF_SIZE];
    int g_ptr = 0;

    int fpm_sock = fcgi_proto_begin_request(selected_ip, selected_port, gather_buf, &g_ptr, request_id);
    if (fpm_sock == -1) return -1;

    // 3. Build & Kirim Params
    fcgi_proto_build_params(req, -1, content_length, gather_buf, &g_ptr, request_id);
    
    // Gunakan safe_send_all (pastikan fungsi ini ada di halmos_fcgi_proto.c atau header)
    if (safe_send_all(fpm_sock, gather_buf, g_ptr) < 0) {
        //fprintf(stderr, "[ERROR-FCGI] Gagal mengirim PARAMS ke backend\n");
        close(fpm_sock);
        return -1;
    }

    // 4. Kirim Body & EOF (Satu Paket)
    // Fungsi ini sekarang menangani pengiriman data CHUNKED dan ditutup dengan EOF tunggal.
    /*if (content_length > 0) {
        fprintf(stderr, "[DEBUG-POST] Mengirim body sebesar %zu bytes\n", content_length);
    }*/
    
    // Panggilan ini krusial: Jika content_length 0, dia tetap kirim EOF. 
    // Jika > 0, dia kirim Data + EOF.
    fcgi_proto_send_stdin(fpm_sock, request_id, post_data, (int)content_length);

    // --- 5. LOGIKA UNBOXING RESPON ---
    size_t capacity = 65536; 
    char *res = malloc(capacity);
    if (!res) {
        close(fpm_sock);
        return -1;
    }
    size_t total_payload = 0;

    unsigned char fcgi_header[8];
    //fprintf(stderr, "[TRACE-FCGI] Memulai pembacaan record dari PHP-FPM...\n");

    while (recv(fpm_sock, fcgi_header, 8, 0) == 8) {
        unsigned char type = fcgi_header[1];
        uint16_t content_len = (fcgi_header[4] << 8) | fcgi_header[5];
        unsigned char padding_len = fcgi_header[6];

        if (content_len > 0) {
            if (type == FCGI_STDOUT) { // Type 6
                while (total_payload + content_len > capacity) {
                    capacity *= 2; // Progressive resize
                    res = realloc(res, capacity);
                }
                
                ssize_t n = 0;
                while (n < content_len) {
                    ssize_t r = recv(fpm_sock, res + total_payload + n, content_len - n, 0);
                    if (r <= 0) break;
                    n += r;
                }
                total_payload += content_len;
            } else if (type == FCGI_STDERR) { // Type 7
                // Opsional: Log error dari PHP ke terminal Halmos
                char *err_msg = malloc(content_len + 1);
                recv(fpm_sock, err_msg, content_len, 0);
                err_msg[content_len] = '\0';
                //fprintf(stderr, "[PHP-STDERR] %s\n", err_msg);
                free(err_msg);
            } else {
                // Skip record tipe lain (misal Management Record)
                unsigned char junk[65536];
                recv(fpm_sock, junk, content_len, 0);
            }
        }

        // Buang padding
        if (padding_len > 0) {
            unsigned char pad[255];
            recv(fpm_sock, pad, padding_len, 0);
        }

        if (type == FCGI_END_REQUEST) break; // Type 3
    }

    //fprintf(stderr, "[TRACE-FCGI] Total Data Bersih (Payload): %zu bytes\n", total_payload);
    
    close(fpm_sock);
    *out_buf = res;
    return (ssize_t)total_payload;
}

unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    int c;

    // Geser dan tambah (shift and add)
    while ((c = *ip++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}
