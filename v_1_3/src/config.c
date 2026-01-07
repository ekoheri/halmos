#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../include/config.h"

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
        // Menghapus karakter newline di akhir baris
        line[strcspn(line, "\n")] = '\0';

        // Lewati komentar
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        // Menangani bagian [Performance] (atau bagian lainnya)
        if (line[0] == '[') {
            sscanf(line, "[%255[^]]]", section);  // Menyimpan nama section
            continue;
        }

        // Mencari tanda "=" yang memisahkan key dan value
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");

        if (key != NULL && value != NULL) {
            // Hapus spasi di sekitar key dan value
            key = trim(key);
            value = trim(value);

            // Menangani key tertentu
            if (strcmp(key, "server_name") == 0) {
                strncpy(config.server_name, value, sizeof(config.server_name));
            } else if (strcmp(key, "server_port") == 0) {
                config.server_port = atoi(value);  // Konversi ke integer
            } else if (strcmp(key, "document_root") == 0) {
                strncpy(config.document_root, value, sizeof(config.document_root));
            } else if (strcmp(key, "default_page") == 0) {
                strncpy(config.default_page, value, sizeof(config.default_page));
            } else if (strcmp(key, "request_buffer_size") == 0) {
                config.request_buffer_size = atoi(value);
            }else if (strcmp(key, "max_body_size") == 0) {
                config.max_body_size = (size_t)atoll(value);
            }else if (strcmp(key, "server_fpm") == 0) {
                strncpy(config.server_fpm, value, sizeof(config.server_fpm));
            } else if (strcmp(key, "port_fpm") == 0) {
                config.port_fpm = atoi(value);
            } else if (strcmp(key, "max_event") == 0) {
                config.max_event = atoi(value);
            } else if (strcmp(key, "secure_application") == 0) {
                // Bandingkan nilainya, jika stringnya "true", set bool menjadi true
                if (strcasecmp(value, "true") == 0) {
                    config.secure_application = true;
                } else {
                    config.secure_application = false;
                }
            }
        }
    }

    fclose(file);
}
