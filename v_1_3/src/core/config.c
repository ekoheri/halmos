#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../include/core/config.h"

// Inisialisasi variabel global config
Config config = {0};

char *trim(char *str) {
    char *end;

    // Hapus spasi di depan
    while (isspace((unsigned char)*str)) {
        str++;
    }

    // Jika hanya ada spasi
    if (*str == 0) {
        return str;
    }

    // Hapus spasi di belakang
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    // Tambahkan null-terminator setelah karakter terakhir yang bukan spasi
    *(end + 1) = '\0';

    return str;
}

// Fungsi untuk membaca file konfigurasi
void load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening config file");
        return;
    }

    char line[1024];  // Buffer untuk membaca setiap baris
    char section[256];  // Menyimpan nama section (misalnya [Performance])

    while (fgets(line, sizeof(line), file)) {
        // 1. Bersihkan newline (Pertahankan kode Anda)
        line[strcspn(line, "\n")] = '\0';

        // 2. Gunakan trim dulu (PENTING!)
        // Supaya jika ada baris "   # Komentar", tetap terdeteksi sebagai komentar
        char *current_line = trim(line);

        // 3. Lewati baris kosong atau komentar (Lebih aman dari line[0])
        if (current_line[0] == '#' || current_line[0] == '\0') {
            continue;
        }

        // 4. Potong komentar di tengah baris (Fitur Tambahan)
        // Agar "8080 # Port" menjadi "8080"
        char *inline_comment = strchr(current_line, '#');
        if (inline_comment) *inline_comment = '\0';

        // 5. Menangani bagian [Section] (Gunakan current_line hasil trim)
        if (current_line[0] == '[') {
            sscanf(current_line, "[%255[^]]]", section);
            continue;
        }

        // 6. Sisanya (strtok, dll) gunakan current_line yang sudah bersih
        // Mencari tanda "=" yang memisahkan key dan value
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");

        if (key != NULL && value != NULL) {
            // Hapus spasi di sekitar key dan value
            key = trim(key);
            value = trim(value);

            // Menangani key pada config
            //network
            if (strcmp(key, "server_name") == 0) {
                strncpy(config.server_name, value, sizeof(config.server_name));
            } else if (strcmp(key, "server_port") == 0) {
                config.server_port = atoi(value);  // Konversi ke integer
            //Storage
            } else if (strcmp(key, "document_root") == 0) {
                strncpy(config.document_root, value, sizeof(config.document_root));
            } else if (strcmp(key, "default_page") == 0) {
                strncpy(config.default_page, value, sizeof(config.default_page));
            //Security
            } else if (strcmp(key, "max_body_size") == 0) {
                config.max_body_size = (size_t)atoll(value);
            } else if (strcmp(key, "secure_application") == 0) {
                // Bandingkan nilainya, jika stringnya "true", set bool menjadi true
                if (strcasecmp(value, "true") == 0) {
                    config.secure_application = true;
                } else {
                    config.secure_application = false;
                }
            // backend PHP
            } else if (strcmp(key, "php_server") == 0) {
                strncpy(config.php_server, value, sizeof(config.php_server));
            } else if (strcmp(key, "php_port") == 0) {
                config.php_port = atoi(value);
            // backend Rust
            } else if (strcmp(key, "rust_ext") == 0) {
                strncpy(config.rust_ext, value, sizeof(config.rust_ext));
            } else if (strcmp(key, "rust_server") == 0) {
                strncpy(config.rust_server, value, sizeof(config.rust_server));
            } else if (strcmp(key, "rust_port") == 0) {
                config.rust_port = atoi(value);
            //Performance
            } else if (strcmp(key, "request_buffer_size") == 0) {
                config.request_buffer_size = atoi(value);
            } else if (strcmp(key, "max_queue_size") == 0) {
                config.max_queue_size = atoi(value);
            }  
        }
    }

    fclose(file);
}
