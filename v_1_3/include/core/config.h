#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

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
    //Backend_PHP
    char php_server[256];
    int php_port;
    //Backend_Rust
    char rust_ext[256];
    char rust_server[256];
    int rust_port;
    //Performance    
    int request_buffer_size;
    int max_queue_size;
} Config;

// Deklarasikan variabel global untuk menyimpan konfigurasi
extern Config config;

//Fungsi untuk membersihkan spasi diawal dan diakhir string
char *trim(char *str);

// Fungsi untuk memuat konfigurasi dari file
void load_config(const char *filename);

#endif
