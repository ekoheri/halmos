#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h> // Untuk strcasecmp

#include "halmos_config.h"
#include "halmos_global.h"
#include "halmos_log.h"

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
        write_log("[ERROR : config.c] Error opening config file");
        return;
    }

    char line[1024];  // Buffer untuk membaca setiap baris
    char section[256];  // Menyimpan nama section (misalnya [Performance])

    while (fgets(line, sizeof(line), file)) {
        // 1. Bersihkan newline
        line[strcspn(line, "\n")] = '\0';

        // 2. Gunakan trim dulu
        char *current_line = trim(line);

        // 3. Lewati baris kosong atau komentar
        if (current_line[0] == '#' || current_line[0] == '\0') {
            continue;
        }

        // 4. Potong komentar di tengah baris
        char *inline_comment = strchr(current_line, '#');
        if (inline_comment) *inline_comment = '\0';

        // 5. Menangani bagian [Section]
        if (current_line[0] == '[') {
            sscanf(current_line, "[%255[^]]]", section);
            continue;
        }

        // 6. Sisanya gunakan strtok
        char *key = strtok(current_line, "=");
        char *value = strtok(NULL, "=");

        if (key != NULL && value != NULL) {
            key = trim(key);
            value = trim(value);

            // --- LOGIKA KHUSUS VIRTUAL HOSTS ---
            if (strcmp(section, "VirtualHosts") == 0) {
                if (config.vhost_count < 32) {
                    // Mengganti strncpy dengan snprintf untuk menghilangkan warning
                    snprintf(config.vhosts[config.vhost_count].host, sizeof(config.vhosts[0].host), "%s", key);
                    snprintf(config.vhosts[config.vhost_count].root, sizeof(config.vhosts[0].root), "%s", value);
                    config.vhost_count++;
                }
                continue;
            }

            // Network
            if (strcmp(key, "server_name") == 0) {
                snprintf(config.server_name, sizeof(config.server_name), "%s", value);
            } else if (strcmp(key, "server_port") == 0) {
                config.server_port = atoi(value);
            // Storage
            } else if (strcmp(key, "document_root") == 0) {
                snprintf(config.document_root, sizeof(config.document_root), "%s", value);
            } else if (strcmp(key, "default_page") == 0) {
                snprintf(config.default_page, sizeof(config.default_page), "%s", value);
            // Security
            } else if (strcmp(key, "max_body_size") == 0) {
                config.max_body_size = (size_t)atoll(value);
            } else if (strcmp(key, "secure_application") == 0) {
                if (strcasecmp(value, "true") == 0) {
                    config.secure_application = true;
                } else {
                    config.secure_application = false;
                }
            } else if (strcmp(key, "rate_limit_enabled") == 0) {
                if (strcasecmp(value, "true") == 0) {
                    config.rate_limit_enabled = true;
                } else {
                    config.rate_limit_enabled = false;
                }
            } else if (strcmp(key, "anti_slow_loris_enabled") == 0) {
                if (strcasecmp(value, "true") == 0) {
                    config.anti_slow_loris_enabled = true;
                } else {
                    config.anti_slow_loris_enabled = false;
                }
            } else if (strcmp(key, "max_requests_per_sec") == 0) {
                config.max_requests_per_sec = atoi(value);
            } else if (strcmp(key, "keep_alive_timeout") == 0) {
                config.keep_alive_timeout = atoi(value);
            // Backend PHP
            } else if (strcmp(key, "php_server") == 0) {
                snprintf(config.php_server, sizeof(config.php_server), "%s", value);
            } else if (strcmp(key, "php_port") == 0) {
                config.php_port = atoi(value);
            // Backend Rust
            } else if (strcmp(key, "rust_ext") == 0) {
                snprintf(config.rust_ext, sizeof(config.rust_ext), "%s", value);
            } else if (strcmp(key, "rust_server") == 0) {
                snprintf(config.rust_server, sizeof(config.rust_server), "%s", value);
            } else if (strcmp(key, "rust_port") == 0) {
                config.rust_port = atoi(value);
            // Backend Python
            } else if (strcmp(key, "python_ext") == 0) {
                snprintf(config.python_ext, sizeof(config.python_ext), "%s", value);
            } else if (strcmp(key, "python_server") == 0) {
                snprintf(config.python_server, sizeof(config.python_server), "%s", value);
            } else if (strcmp(key, "python_port") == 0) {
                config.python_port = atoi(value);
            // Performance
            } else if (strcmp(key, "request_buffer_size") == 0) {
                config.request_buffer_size = atoi(value);
            } else if (strcmp(key, "max_queue_size") == 0) {
                config.max_queue_size = atoi(value);
            }  
        }
    }

    fclose(file);
}