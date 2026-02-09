#include "halmos_route.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Definisi variabel global
RouteRule route_table[MAX_ROUTES];
int total_routes = 0;

/**
 * Fungsi internal untuk memecah target (script + query)
 * Misal: "index.php?id=1" jadi script_name="index.php" dan query_args="id=1"
 */
static void parse_target(RouteRule *rule, char *target_raw) {
    char *q_mark = strchr(target_raw, '?');
    if (q_mark) {
        *q_mark = '\0'; 
        // %.127s memaksa snprintf berhenti di 127 karakter, 
        // ini yang bikin GCC akhirnya diam karena "pasti muat" di 128 byte.
        snprintf(rule->script_name, sizeof(rule->script_name), "%.127s", target_raw);
        snprintf(rule->query_args, sizeof(rule->query_args), "%.127s", q_mark + 1);
    } else {
        snprintf(rule->script_name, sizeof(rule->script_name), "%.127s", target_raw);
        rule->query_args[0] = '\0';
    }
}
/**
 * Memuat rute dari file halmos_route.conf
 */
void load_routes(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("[ROUTER] Gagal buka %s, pake default mode.\n", filename);
        return;
    }

    char line[512];
    total_routes = 0;

    while (fgets(line, sizeof(line), file) && total_routes < MAX_ROUTES) {
        // Abaikan komentar (#) atau baris kosong
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || line[0] == ' ') continue;

        char path_tmp[128], type_str[32], target_tmp[256];
        
        // Membaca 3 kolom: Path, Tipe, Target
        if (sscanf(line, "%127s %31s %255s", path_tmp, type_str, target_tmp) == 3) {
            RouteRule *rule = &route_table[total_routes];
            
            // 1. Cek Wildcard (Contoh: /assets/*)
            char *star = strchr(path_tmp, '*');
            if (star) {
                rule->is_wildcard = true;
                *star = '\0'; // Potong agar jadi prefix saja
            } else {
                rule->is_wildcard = false;
            }
            
            // Simpan pattern ke struct
            snprintf(rule->pattern, sizeof(rule->pattern), "%s", path_tmp);

            // 2. Mapping Tipe Rute
            if (strcmp(type_str, "STATIC") == 0)             rule->type = RT_STATIC;
            else if (strcmp(type_str, "FASTCGI_PHP") == 0)   rule->type = RT_FASTCGI_PHP;
            else if (strcmp(type_str, "FASTCGI_RS") == 0)    rule->type = RT_FASTCGI_RS;
            else if (strcmp(type_str, "FASTCGI_PY") == 0)    rule->type = RT_FASTCGI_PY;
            else if (strcmp(type_str, "FALLBACK") == 0)      rule->type = RT_FALLBACK;
            else rule->type = RT_STATIC; // Default

            // 3. Parse target_tmp (Pecah script dan query)
            parse_target(rule, target_tmp);

            total_routes++;
        }
    }
    fclose(file);
    printf("[ROUTER] Berhasil muat %d rute dari %s\n", total_routes, filename);
}

/**
 * Mencocokkan URI request dengan tabel rute
 */
RouteRule* match_route(const char *uri) {
    printf("[DEBUG] Mencoba mencocokkan URI: '%s'\n", uri);
    for (int i = 0; i < total_routes; i++) {
        printf("[DEBUG] Membandingkan dengan rute: '%s'\n", route_table[i].pattern);
        if (route_table[i].is_wildcard) {
            // Cocokkan awalan (Prefix Match)
            if (strncmp(uri, route_table[i].pattern, strlen(route_table[i].pattern)) == 0) {
                return &route_table[i];
            }
        } else {
            // Cocokkan persis (Exact Match)
            if (strcmp(uri, route_table[i].pattern) == 0) {
                return &route_table[i];
            }
        }
    }
    return NULL; 
}