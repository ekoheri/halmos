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

int fcgi_api_request_stream(RequestHeader *req, int sock_client, int backend_type, void *post_data, size_t content_length) {
    // 1. Siapkan pointer untuk menunjuk ke grup yang benar
    UpstreamGroup *live_group;   // Data hidup (next_idx) di fcgi_pool
    BackendGroup  *cfg_group;    // Data statis (ips, ports) di config
    
    // 2. Mapping berdasarkan backend_type
    if (backend_type == 0) {
        live_group = &fcgi_pool.php_group;
        cfg_group  = &config.php;
    } else if (backend_type == 1) {
        live_group = &fcgi_pool.rust_group;
        cfg_group  = &config.rust;
    } else {
        live_group = &fcgi_pool.python_group;
        cfg_group  = &config.python;
    }

    // 3. Validasi: pastikan ada node yang tersedia
    if (cfg_group->node_count <= 0) {
        write_log_error("[FCGI] No nodes configured for backend type %d", backend_type);
        return -1;
    }

    /*
    [TIANG UTAMA: LOAD BALANCER]
    Menggunakan Atomic Fetch & Add agar pemilihan node 100% thread-safe tanpa lock mutex.
    Modulo (%) node_count memastikan giliran selalu kembali ke node pertama (Round Robin).
    */

    int idx;
    if (strcmp(cfg_group->lb_strategy, "ip_hash") == 0) {
        idx = hash_ip(req->client_ip) % cfg_group->node_count;
    } else {
        idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    }
    
    // Ambil IP dan Port spesifik dari config berdasarkan index terpilih
    const char *selected_ip = cfg_group->ips[idx];
    int selected_port       = cfg_group->ports[idx];

    // --- LANJUT KE PROSES FCGI ---
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
