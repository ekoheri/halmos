#include "halmos_route.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#define route_config_filename "/etc/halmos/route.conf"

// Definisi variabel global
RouteTable g_routes[MAX_ROUTES];
int g_total_routes = 0;
static time_t last_file_mtime = 0;

// Helper internal untuk konversi string ke Enum
RouteType parse_route_type(const char *s) {
    if (strcmp(s, "QUERY") == 0) return RT_QUERY;
    if (strcmp(s, "PATH") == 0) return RT_PATH;
    return RT_NONE;
}

FcgiBackend parse_fcgi_type(const char *s) {
    if (strcmp(s, "FCGI_PY") == 0) return FCGI_PY;
    if (strcmp(s, "FCGI_RS") == 0) return FCGI_RS;
    return FCGI_PHP;
}

void load_routes() {
    FILE *fp = fopen(route_config_filename, "r");
    if (!fp) return;

    g_total_routes = 0;
    char line[512];
    
    while (fgets(line, sizeof(line), fp) && g_total_routes < MAX_ROUTES) {
        // Abaikan komentar dan baris kosong
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        RouteTable *rt = &g_routes[g_total_routes];
        char type_str[16], fcgi_str[16], vars_str[256] = {0};
        
        // Parsing kolom menggunakan sscanf dengan delimiter '|'
        // Format: Type | Source | Target | FCGI Type | [Var Name]
        int n = sscanf(line, "%[^|]|%[^|]|%[^|]|%[^|]|%[^\n]", 
                       type_str, rt->source, rt->target, fcgi_str, vars_str);

        if (n >= 4) {
            // Trim spasi untuk tiap kolom string
            trim_util(type_str); trim_util(rt->source); 
            trim_util(rt->target); trim_util(fcgi_str);

            rt->type = parse_route_type(type_str);
            rt->fcgi_type = parse_fcgi_type(fcgi_str);
            rt->var_count = 0;

            // Jika ada variabel di dalam [nama, alamat]
            if (n == 5 && rt->type == RT_QUERY) {
                char *start = strchr(vars_str, '[');
                char *end = strchr(vars_str, ']');
                if (start && end) {
                    *end = '\0'; // Tutup string di ']'
                    char *token = strtok(start + 1, ",");
                    while (token && rt->var_count < MAX_VAR_COUNT) {
                        trim_util(token);
                        strncpy(rt->var_names[rt->var_count++], token, MAX_VAR_NAME_LEN - 1);
                        token = strtok(NULL, ",");
                    }
                }
            }
            g_total_routes++;
        }
    }
    fclose(fp);
    printf("[ROUTER] %d routes loaded successfully.\n", g_total_routes);
}

void halmos_router_auto_reload() {
    static time_t last_check = 0;
    time_t now = time(NULL);

    if (now - last_check < 5) return;
    last_check = now;

    struct stat st;
    if (stat(route_config_filename, &st) == 0) {
        if (st.st_mtime > last_file_mtime) {
            load_routes();
            last_file_mtime = st.st_mtime;
        }
    } else {
        // write_log_error("[ROUTER-ERROR] File %s NOT FOUND!", route_config_filename);
    }
}

void trim_util(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

/**
 * Mencari rute yang cocok berdasarkan awalan (prefix) URI.
 * Kita mencari match yang paling panjang/spesifik terlebih dahulu.
 */
RouteTable* match_route(const char *uri) {
    RouteTable *best_match = NULL;
    size_t max_len = 0;

    for (int i = 0; i < g_total_routes; i++) {
        size_t source_len = strlen(g_routes[i].source);
        
        // Cek apakah URI dimulai dengan g_routes[i].source
        if (strncmp(uri, g_routes[i].source, source_len) == 0) {
            // Logika: ambil match yang paling panjang (paling spesifik)
            // Contoh: /login-admin lebih spesifik daripada /login
            if (source_len > max_len) {
                max_len = source_len;
                best_match = &g_routes[i];
            }
        }
    }
    return best_match;
}

/**
 * Melakukan transformasi URL berdasarkan tipe rute (NONE, QUERY, PATH).
 */
void apply_route_logic(RouteTable *match, const char *original_uri, char *out_target, char *out_query, char *out_path_info) {
    // 1. Tentukan file mana yang akan dieksekusi (Target)
    // original_uri: "/p/1" -> out_target: "/produk.php"
    strcpy(out_target, match->target);

    // 2. Ambil sisa setelah source
    // Misal source "/p", original_uri "/p/1", maka remainder adalah "/1"
    const char *remainder = original_uri + strlen(match->source);

    if (match->type == RT_NONE) {
        out_query[0] = '\0';
        out_path_info[0] = '\0';
    } 
    else if (match->type == RT_PATH) {
        // Tipe PATH: /info-path/user/123 -> out_path_info: "/user/123"
        strcpy(out_path_info, remainder);
        out_query[0] = '\0';
    } 
    else if (match->type == RT_QUERY) {
        // Tipe QUERY: /p/1 -> out_query: "id=1"
        out_path_info[0] = '\0';
        out_query[0] = '\0';

        char temp[256];
        strncpy(temp, remainder, sizeof(temp)-1);
        
        // Buang slash di depan (/1 jadi 1)
        char *p = temp;
        if (*p == '/') p++;

        int var_idx = 0;
        char *token = strtok(p, "/");
        while (token && var_idx < match->var_count) {
            char pair[128];
            // Susun: "id=1" atau "&alamat=malang"
            snprintf(pair, sizeof(pair), "%s%s=%s", 
                     (var_idx > 0 ? "&" : ""), 
                     match->var_names[var_idx], 
                     token);
            strcat(out_query, pair);
            token = strtok(NULL, "/");
            var_idx++;
        }
    }
}