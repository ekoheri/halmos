#ifndef HALMOS_CONFIG_H
#define HALMOS_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char host[256];
    char root[1024];
} VHostEntry;

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
    bool secure_application;
    bool rate_limit_enabled;
    bool anti_slow_loris_enabled;
    int max_requests_per_sec;
    int keep_alive_timeout;
    //Backend_PHP
    char php_server[256];
    int php_port;
    char php_fpm_config_path[512];
    //Backend_Rust
    char rust_ext[256];
    char rust_server[256];
    int rust_port;
    //Backend_Python
    char python_ext[256];
    char python_server[256];
    int python_port;
    //Performance    
    int request_buffer_size;
    //Virtual Host
    VHostEntry vhosts[32];    // Bisa nampung 32 domain
    int vhost_count;
} Config;

//Fungsi untuk membersihkan spasi diawal dan diakhir string
char *trim(char *str);

// Fungsi untuk memuat konfigurasi dari file
void load_config(const char *filename);

#endif
