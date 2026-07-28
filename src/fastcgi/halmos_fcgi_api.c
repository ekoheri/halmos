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

// =========================================================================
// HELPER: Membaca pas N byte dari socket TCP sampai tuntas.
// Mencegah data terpotong (truncated) akibat perilaku paket TCP.
// =========================================================================
static ssize_t recv_exact(int fd, void *buf, size_t len) {
    size_t total_read = 0;
    char *ptr = (char *)buf;

    while (total_read < len) {
        ssize_t n = recv(fd, ptr + total_read, len - total_read, 0);
        if (n < 0) {
            return -1; // Socket error
        }
        if (n == 0) {
            break; // Socket ditutup oleh backend
        }
        total_read += n;
    }
    return (ssize_t)total_read;
}

/**
 * fcgi_api_request_http2
 * Khusus untuk HTTP/2: Tidak menulis langsung ke socket client.
 * Mengembalikan seluruh output backend (Header + Body) ke dalam *out_buf.
 */

ssize_t fcgi_api_request_http2(RequestHeader *req, int backend_type, void *post_data, size_t content_length, char **out_buf) {
    if (!req || !out_buf) return -1;

    VHostEntry *vh = (VHostEntry *)req->vhost_context; 
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

    int request_id = 1;
    unsigned char gather_buf[GATHER_BUF_SIZE];
    int g_ptr = 0;

    int fpm_sock = fcgi_proto_begin_request(selected_ip, selected_port, gather_buf, &g_ptr, request_id);
    if (fpm_sock == -1) return -1;

    fcgi_proto_build_params(req, -1, content_length, gather_buf, &g_ptr, request_id);
    
    if (safe_send_all(fpm_sock, gather_buf, g_ptr) < 0) {
        close(fpm_sock);
        return -1;
    }

    fcgi_proto_send_stdin(fpm_sock, request_id, post_data, (int)content_length);

    size_t capacity = 65536; 
    char *res = malloc(capacity);
    if (!res) {
        close(fpm_sock);
        return -1;
    }
    size_t total_payload = 0;
    unsigned char fcgi_header[8];

    // =========================================================================
    // 🔍 [INSTRUMENTASI DEBUG FASTCGI RESPONSE RECORDS FROM PHP-FPM]
    // =========================================================================
    fprintf(stderr, "\n==================== [DEBUG FCGI UNBOXING LOOP] ====================\n");
    int record_count = 0;

    while (1) {
        ssize_t h_read = recv_exact(fpm_sock, fcgi_header, 8);
        if (h_read < 8) {
            fprintf(stderr, "[UNBOX-LOOP] Header read < 8 (%zd bytes). Socket closed/EOF!\n", h_read);
            break; 
        }

        record_count++;
        unsigned char type     = fcgi_header[1];
        uint16_t content_len   = (fcgi_header[4] << 8) | fcgi_header[5];
        unsigned char pad_len  = fcgi_header[6];

        fprintf(stderr, "[RECORD #%d] Type: %d (0x%02X) | ContentLen: %u | PadLen: %u\n", 
                record_count, type, type, content_len, pad_len);

        if (content_len > 0) {
            if (type == 0x06) { // FCGI_STDOUT
                while (total_payload + content_len >= capacity) {
                    capacity *= 2; 
                    char *new_res = realloc(res, capacity);
                    if (!new_res) {
                        free(res);
                        close(fpm_sock);
                        return -1;
                    }
                    res = new_res;
                }
                
                ssize_t payload_read = recv_exact(fpm_sock, res + total_payload, content_len);
                fprintf(stderr, "   --> STDOUT Chunk Read: %zd bytes\n", payload_read);
                if (payload_read > 0) {
                    // Print isi chunk-nya di stderr untuk inspeksi visual langsung!
                    fprintf(stderr, "   --> Chunk Content:\n%.*s\n", (int)payload_read, res + total_payload);
                    total_payload += (size_t)payload_read;
                }
            } else if (type == 0x07) { // FCGI_STDERR
                char *err_buf = malloc(content_len + 1);
                if (err_buf) {
                    recv_exact(fpm_sock, err_buf, content_len);
                    err_buf[content_len] = '\0';
                    fprintf(stderr, "   [PHP-STDERR] %s\n", err_buf);
                    free(err_buf);
                }
            } else {
                size_t skipped = 0;
                char junk[1024];
                while (skipped < content_len) {
                    size_t chunk = (content_len - skipped > sizeof(junk)) ? sizeof(junk) : (content_len - skipped);
                    ssize_t r = recv_exact(fpm_sock, junk, chunk);
                    if (r <= 0) break;
                    skipped += (size_t)r;
                }
            }
        }

        if (pad_len > 0) {
            char pad_junk[256];
            recv_exact(fpm_sock, pad_junk, pad_len);
        }

        if (type == 0x03) { // FCGI_END_REQUEST
            fprintf(stderr, "[UNBOX-LOOP] Menerima FCGI_END_REQUEST (Type 3). Selesai.\n");
            break; 
        }
    }

    fprintf(stderr, "==================== [TOTAL PAYLOAD READ: %zu BYTES] ====================\n\n", total_payload);

    if (total_payload >= capacity) {
        char *new_res = realloc(res, total_payload + 1);
        if (new_res) res = new_res;
    }
    res[total_payload] = '\0';

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
