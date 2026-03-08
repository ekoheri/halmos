#ifndef HALMOS_CONFIG_H
#define HALMOS_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "halmos_http_route.h"

#define MAX_BACKEND_NODES 8 // Maksimal 8 server per grup

struct VHostEntry{
    char host[256];
    char root[1024];
    
    /* --- TAMBAHAN FIELD UNTUK MODUL ROUTE (SI TAMU) --- */
    RouteTable routes[MAX_ROUTES]; 
    int total_routes;
    time_t last_route_mtime;
    unsigned long long request_count;
};

// Struktur untuk menampung banyak node Load Balancing
typedef struct {
    char ips[MAX_BACKEND_NODES][64]; // Array IP/Path
    int ports[MAX_BACKEND_NODES];    // Array Port
    int node_count;                  // Jumlah node yang terdeteksi
    char ext[16];                    // Ekstensi (untuk Rust/Python)
    char lb_strategy[32];            // round_robin, dll
} BackendGroup;

// Struktur data untuk konfigurasi
typedef struct {
    //Network
    char server_name[256];
    int server_port;
    //Storage
    char document_root[256];
    char default_page[256];
    //Security
    size_t max_body_size; // Misal dalam byte
    bool tls_enabled;
    bool e2ee_enabled;
    char ssl_certificate_file[512];
    char ssl_private_key_file[512];
    bool rate_limit_enabled;
    bool anti_slow_loris_enabled;
    int max_requests_per_sec;
    int keep_alive_timeout;
    bool trust_proxy;

    // --- REFAKTOR BACKEND ---
    BackendGroup php;
    BackendGroup rust;
    BackendGroup python;

    char php_fpm_config_path[512];

    //Performance    
    int request_buffer_size;
    //Virtual Host
    VHostEntry vhosts[32];    // Bisa nampung 32 domain
    int vhost_count;
} Config;

// Fungsi untuk memuat konfigurasi dari file
void core_config_load(const char *filename);

#endif
