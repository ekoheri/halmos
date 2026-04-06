#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h> // Untuk strcasecmp

#include "halmos_core_config.h"
#include "halmos_global.h"
#include "halmos_log.h"

// Inisialisasi variabel global config
Config config = {0};

static char *trim(char *str);

static unsigned long parse_size(const char *str);

static void parse_csv_to_group(char *value, BackendGroup *group, bool is_port);

// Fungsi untuk membaca file konfigurasi
void core_config_load(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        write_log("[ERROR : config.c] Error opening config file");
        return;
    }

    char line[1024];  
    char section[256] = "";  
    int current_vh_idx = -1; // Penanda mode: -1 = Global, 0+ = Index VHost

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';
        char *current_line = trim(line);

        if (current_line[0] == '#' || current_line[0] == '\0') {
            continue;
        }

        char *inline_comment = strchr(current_line, '#');
        if (inline_comment) *inline_comment = '\0';

        // --- 1. DETEKSI SECTION [HEADER] ---
        if (current_line[0] == '[') {
            if (sscanf(current_line, "[%255[^]]]", section) == 1) {
                // Jika Section VHost Spesifik
                if (strncmp(section, "VHost:", 6) == 0) {
                    if (config.vhost_count < 32) {
                        current_vh_idx = config.vhost_count;
                        char *host_name = section + 6; 
                        snprintf(config.vhosts[current_vh_idx].host, sizeof(config.vhosts[0].host), "%s", trim(host_name));
                        
                        // Inisialisasi node_count agar tidak sampah memori
                        config.vhosts[current_vh_idx].python.node_count = 0;
                        config.vhosts[current_vh_idx].php.node_count = 0;
                        config.vhosts[current_vh_idx].rust.node_count = 0;
                        
                        config.vhost_count++;
                    }
                } else {
                    current_vh_idx = -1; // Section global (Network, dll)
                }
            }
            continue;
        }

        char *key = strtok(current_line, "=");
        char *value = strtok(NULL, "=");

        if (key != NULL && value != NULL) {
            key = trim(key);
            value = trim(value);

            // --- 2. LOGIKA JIKA DI DALAM BLOK VHOST ---
            if (current_vh_idx != -1) {
                VHostEntry *vh = &config.vhosts[current_vh_idx];
                
                if (strcmp(key, "root") == 0) {
                    snprintf(vh->root, sizeof(vh->root), "%s", value);
                } 
                else if (strcmp(key, "py_server") == 0) parse_csv_to_group(value, &vh->python, false);
                else if (strcmp(key, "py_port") == 0)   parse_csv_to_group(value, &vh->python, true);
                else if (strcmp(key, "py_lb") == 0)     snprintf(vh->python.lb_strategy, sizeof(vh->python.lb_strategy), "%s", value);
                
                else if (strcmp(key, "php_server") == 0) parse_csv_to_group(value, &vh->php, false);
                else if (strcmp(key, "php_port") == 0)   parse_csv_to_group(value, &vh->php, true);
                else if (strcmp(key, "php_lb") == 0)     snprintf(vh->php.lb_strategy, sizeof(vh->php.lb_strategy), "%s", value);
                
                else if (strcmp(key, "rs_server") == 0)  parse_csv_to_group(value, &vh->rust, false);
                else if (strcmp(key, "rs_port") == 0)   parse_csv_to_group(value, &vh->rust, true);
                else if (strcmp(key, "rs_lb") == 0)     snprintf(vh->rust.lb_strategy, sizeof(vh->rust.lb_strategy), "%s", value);
                
                continue; // Lanjut ke baris berikutnya, jangan tabrakan dengan global
            }

            // --- 3. LOGIKA GLOBAL CONFIG (Lama & Tetap) ---
            // Network
            if (strcmp(key, "server_name") == 0) {
                snprintf(config.server_name, sizeof(config.server_name), "%s", value);
            } else if (strcmp(key, "server_port") == 0) {
                config.server_port = atoi(value);
            } else if (strcmp(key, "document_root") == 0) {
                snprintf(config.document_root, sizeof(config.document_root), "%s", value);
            } else if (strcmp(key, "default_page") == 0) {
                snprintf(config.default_page, sizeof(config.default_page), "%s", value);
            } else if (strcmp(key, "max_body_size") == 0) {
                config.max_body_size = (size_t)parse_size(value);
            } else if (strcmp(key, "tls_enabled") == 0) {
                config.tls_enabled = (strcasecmp(value, "true") == 0);
            } else if (strcmp(key, "e2ee_enabled") == 0) {
                config.e2ee_enabled = (strcasecmp(value, "true") == 0);
            } else if (strcmp(key, "ssl_certificate_file") == 0) {
                snprintf(config.ssl_certificate_file, sizeof(config.ssl_certificate_file), "%s", value);
            } else if (strcmp(key, "ssl_private_key_file") == 0) {
                snprintf(config.ssl_private_key_file, sizeof(config.ssl_private_key_file), "%s", value);
            } else if (strcmp(key, "rate_limit_enabled") == 0) {
                config.rate_limit_enabled = (strcasecmp(value, "true") == 0);
            } else if (strcmp(key, "anti_slow_loris_enabled") == 0) {
                config.anti_slow_loris_enabled = (strcasecmp(value, "true") == 0);
            } else if (strcmp(key, "max_requests_per_sec") == 0) {
                config.max_requests_per_sec = atoi(value);
            } else if (strcmp(key, "keep_alive_timeout") == 0) {
                config.keep_alive_timeout = atoi(value);
            } else if (strcmp(key, "trust_proxy") == 0) {
                config.trust_proxy = (strcasecmp(value, "true") == 0);
            } else if (strcmp(key, "php_server") == 0) {
                parse_csv_to_group(value, &config.php, false);
            } else if (strcmp(key, "php_port") == 0) {
                parse_csv_to_group(value, &config.php, true);
            } else if (strcmp(key, "php_fpm_config_path") == 0) {
                snprintf(config.php_fpm_config_path, sizeof(config.php_fpm_config_path), "%s", value);
            } else if(strcmp(key, "php_lb_strategy") == 0) {
                snprintf(config.php.lb_strategy, sizeof(config.php.lb_strategy), "%s", value);
            } else if (strcmp(key, "rust_ext") == 0) {
                snprintf(config.rust.ext, sizeof(config.rust.ext), "%s", value);
            } else if (strcmp(key, "rust_server") == 0) {
                parse_csv_to_group(value, &config.rust, false);
            } else if (strcmp(key, "rust_port") == 0) {
                parse_csv_to_group(value, &config.rust, true);
            } else if(strcmp(key, "rust_lb_strategy") == 0) {
                snprintf(config.rust.lb_strategy, sizeof(config.rust.lb_strategy), "%s", value);
            } else if (strcmp(key, "python_ext") == 0) {
                snprintf(config.python.ext, sizeof(config.python.ext), "%s", value);
            } else if (strcmp(key, "python_server") == 0) {
                parse_csv_to_group(value, &config.python, false);
            } else if (strcmp(key, "python_port") == 0) {
                parse_csv_to_group(value, &config.python, true);
            } else if(strcmp(key, "python_lb_strategy") == 0) {
                snprintf(config.python.lb_strategy, sizeof(config.python.lb_strategy), "%s", value);
            } else if (strcmp(key, "request_buffer_size") == 0) {
                config.request_buffer_size = atoi(value);
            }
        }
    }

    fclose(file);
}

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

unsigned long parse_size(const char *str) {
    if (str == NULL) return 0;

    char *endptr;
    unsigned long value = strtoul(str, &endptr, 10);

    while (isspace((unsigned char)*endptr)) endptr++;

    // Switch hanya bisa karakter tunggal
    switch (toupper((unsigned char)*endptr)) {
        case 'G': value *= 1024 * 1024 * 1024; break; // Covers G, GB, Gb
        case 'M': value *= 1024 * 1024; break;        // Covers M, MB, Mb
        case 'K': value *= 1024; break;               // Covers K, KB, Kb
    }
    return value;
}

void parse_csv_to_group(char *value, BackendGroup *group, bool is_port) {
    char *token;
    char *rest = value;
    int i = 0;

    while ((token = strtok_r(rest, ",", &rest)) && i < MAX_BACKEND_NODES) {
        char *t = trim(token);
        if (is_port) {
            group->ports[i] = atoi(t);
        } else {
            snprintf(group->ips[i], sizeof(group->ips[0]), "%s", t);
        }
        i++;
    }
    // Update count hanya jika ini adalah parsing IP (asumsi IP adalah wajib)
    if (!is_port) group->node_count = i;
}
