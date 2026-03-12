#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "halmos_fcgi.h"
#include "halmos_global.h"
#include "halmos_log.h"

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

unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    int c;

    // Geser dan tambah (shift and add)
    while ((c = *ip++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}
