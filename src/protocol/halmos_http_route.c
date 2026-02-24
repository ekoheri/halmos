#include "halmos_http_route.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

// #define route_config_filename "/etc/halmos/route.conf"

// Definisi variabel global
RouteTable g_routes[MAX_ROUTES];
int g_total_routes = 0;
static time_t last_file_mtime = 0;

// Helper internal untuk konversi string ke Enum
static RouteType parse_route_type(const char *s);
static FcgiBackend parse_fcgi_type(const char *s);
static void route_load(const char *path_route);
static void trim_util(char *str);

void http_route_auto_reload() {
    static time_t last_check = 0;
    time_t now = time(NULL);

    if (now - last_check < 5) return;
    last_check = now;

    char doc_root_clean[256];
    snprintf(doc_root_clean, sizeof(doc_root_clean), "%s", config.document_root);
    
    // Pakai fungsi trim kamu di sini
    trim_whitespace(doc_root_clean); 

    char path_route[512];
    size_t len = strlen(doc_root_clean);
    
    // Gabungkan path (menangani slash di ujung)
    if (len > 0 && doc_root_clean[len - 1] == '/') {
        snprintf(path_route, sizeof(path_route), "%s.htroute", doc_root_clean);
    } else {
        snprintf(path_route, sizeof(path_route), "%s/.htroute", doc_root_clean);
    }

    struct stat st;
    int res = stat(path_route, &st);
    
    if (res == 0) {
        if (st.st_mtime > last_file_mtime) {
            route_load(path_route);
            last_file_mtime = st.st_mtime;
        }
    } else {
        // INI BAGIAN PENTING: Apa alasan sebenarnya?
        int err_code = errno;
        if (err_code == ENOENT) {
            // File tidak ada, panggil load_routes untuk buat baru
            write_log("[ROUTER] File .htroute not found, attempting to create...");
            route_load(path_route);
        } else {
            // Jika bukan ENOENT, maka ini adalah masalah Izin atau Path Rusak
            write_log_error("[ROUTER] SYSTEM ERROR on path: [%s]", path_route);
            write_log_error("[ROUTER] REASON: %s (errno: %d)", strerror(err_code), err_code);
        }
    }
}

/**
 * Mencari rute yang cocok berdasarkan awalan (prefix) URI.
 * Kita mencari match yang paling panjang/spesifik terlebih dahulu.
 */
RouteTable* http_route_match(const char *uri) {
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
void http_route_apply_logic(RouteTable *match, const char *original_uri, char *out_target, char *out_query, char *out_path_info) {
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

void route_load(const char *path_route) {
    FILE *fp = fopen(path_route, "r");
    if (!fp) {
        // Jika file tidak ditemukan (errno == ENOENT), buat file baru yang kosong
        if (errno == ENOENT) {
            fp = fopen(path_route, "w");
            if (fp) {
                fprintf(fp, "# Halmos Dynamic Route Configuration\n");
                fclose(fp);
                write_log("[ROUTER] Created new empty config file: %s", path_route);
            }
            // Setelah dibuat, g_total_routes tetap 0 karena file kosong
            g_total_routes = 0;
            return;
        } else {
            write_log_error("[ROUTER] Cannot access config file: %s", path_route);
            return;
        }
    }

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
    write_log("[ROUTER] Successfully loaded %d routes from config", g_total_routes);
}

void trim_util(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}