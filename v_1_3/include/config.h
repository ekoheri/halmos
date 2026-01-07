#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

// Struktur data untuk konfigurasi
typedef struct {
    char server_name[256];
    int server_port;
    char document_root[256];
    char default_page[256];
    int request_buffer_size;
    size_t max_body_size; // Misal dalam byte
    char server_fpm[256];
    int port_fpm;
    int max_event;
    bool secure_application;
} Config;

// Deklarasikan variabel global untuk menyimpan konfigurasi
extern Config config;

//Fungsi untuk membersihkan spasi diawal dan diakhir string
char *trim(char *str);

// Fungsi untuk memuat konfigurasi dari file
void load_config(const char *filename);

#endif
