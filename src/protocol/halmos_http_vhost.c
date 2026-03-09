#include "halmos_http_vhost.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

static void _vhost_load_single_route_file(VHostEntry *vh, const char *path);

/**
 * Mencari pointer ke struktur VHost berdasarkan header Host.
 * Jika tidak ditemukan, akan mengembalikan default context (jika ada).
 */
VHostEntry* http_vhost_get_context(const char *incoming_host) {
    if (!incoming_host) return NULL;

    // 1. Bersihkan incoming_host dari port (misal: localhost:8080 -> localhost)
    char clean_host[128];
    strncpy(clean_host, incoming_host, sizeof(clean_host) - 1);
    clean_host[sizeof(clean_host) - 1] = '\0';
    
    char *port_ptr = strchr(clean_host, ':');
    if (port_ptr) *port_ptr = '\0';

    // 2. Logika SKIP WWW (p_host)
    const char *p_host = clean_host;
    if (strncasecmp(clean_host, "www.", 4) == 0) {
        p_host += 4;
    }

    // 3. Iterasi mencari yang cocok di config global
    // config.vhosts adalah array HalmosVHost yang sudah diparsing dari halmos.conf
    for (int i = 0; i < config.vhost_count; i++) {
        // Cek domain asli atau domain tanpa www
        if (strcasecmp(config.vhosts[i].host, clean_host) == 0 || 
            strcasecmp(config.vhosts[i].host, p_host) == 0) {
            
            // Increment request count untuk statistik Monitor API
            config.vhosts[i].request_count++;
            return &config.vhosts[i];
        }
    }

    return NULL; // Tidak ditemukan
}

/**
 * Inisialisasi awal. Memastikan semua VHost mulai dengan 0 rute
 * dan melakukan load awal untuk semua .htroute yang tersedia.
 */
void http_vhost_init_all() {
    //fprintf(stderr, "[DEBUG] Masuk http_vhost_init_all, count: %d\n", config.vhost_count);
    
    for (int i = 0; i < config.vhost_count; i++) {
        //fprintf(stderr, "[DEBUG] Init vhost index %d: %s\n", i, config.vhosts[i].host);
        config.vhosts[i].total_routes = 0;
        config.vhosts[i].last_route_mtime = 0;
        config.vhosts[i].request_count = 0;
    }
    
    //fprintf(stderr, "[DEBUG] Memanggil reload_routes awal...\n");
    http_vhost_reload_routes();
    //fprintf(stderr, "[DEBUG] Keluar http_vhost_init_all\n");
}

void http_vhost_reload_routes() {
    // Hapus static timer dulu buat debug supaya setiap dipanggil pasti jalan
    static time_t last_check_time = 0;
    time_t now = time(NULL);

    // GERBANG: Cek file cuma setiap 5 detik sekali
    if (now - last_check_time < 5) {
        return; 
    }
    last_check_time = now;

    //fprintf(stderr, "[DEBUG] Masuk http_vhost_reload_routes\n");
    
    for (int i = 0; i < config.vhost_count; i++) {
        char path_route[512];
        char root_clean[256];
        
        if (config.vhosts[i].root[0] == '\0') {
            //fprintf(stderr, "[DEBUG] VHost %d root kosong, skip\n", i);
            continue;
        }

        strncpy(root_clean, config.vhosts[i].root, sizeof(root_clean)-1);
        root_clean[sizeof(root_clean)-1] = '\0';
        trim_whitespace(root_clean);

        size_t len = strlen(root_clean);
        if (len > 0 && root_clean[len-1] == '/') {
            snprintf(path_route, sizeof(path_route), "%s.htroute", root_clean);
        } else {
            snprintf(path_route, sizeof(path_route), "%s/.htroute", root_clean);
        }

        //fprintf(stderr, "[DEBUG] Checking file: %s\n", path_route);
        struct stat st;
        if (stat(path_route, &st) == 0) {
            // FILE ADA: Baru proses kalau mtime berubah
            if (st.st_mtime > config.vhosts[i].last_route_mtime) {
                _vhost_load_single_route_file(&config.vhosts[i], path_route);
                config.vhosts[i].last_route_mtime = st.st_mtime;
                write_log("[VHOST] Routes updated for %s", config.vhosts[i].host);
            }
        } else {
            // FILE TIDAK ADA: Cukup pastikan rute nol dan mtime reset
            // Tidak perlu fprintf/error karena ini kondisi normal
            if (config.vhosts[i].total_routes > 0) {
                config.vhosts[i].total_routes = 0;
                config.vhosts[i].last_route_mtime = 0;
            }
        }
    }
    //fprintf(stderr, "[DEBUG] Keluar http_vhost_reload_routes\n");
}

/*
FUNGSI HELPER
*/

void _vhost_load_single_route_file(VHostEntry *vh, const char *path) {
    if (!vh) return;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        // Jika file tidak bisa dibuka, kita biarkan rute lama tetap ada 
        // atau bisa log error sesuai kebutuhan
        return; 
    }

    // Gunakan variabel sementara untuk menghitung rute yang berhasil di-parse
    int temp_count = 0;
    char line[512];
    
    // Kita bersihkan dulu buffer rute sementara di vh (opsional tapi bagus untuk keamanan data)
    // memset(vh->routes, 0, sizeof(vh->routes));

    while (fgets(line, sizeof(line), fp) && temp_count < MAX_ROUTES) {
        // Skip baris komentar (#) atau baris kosong
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || line[0] == ' ') continue;

        RouteTable *rt = &vh->routes[temp_count];
        char type_str[16], fcgi_str[16], vars_str[256] = {0};
        
        // Parsing dengan delimiter |
        // Format: TYPE|SOURCE|TARGET|FCGI_TYPE|VARS
        int n = sscanf(line, "%[^|]|%[^|]|%[^|]|%[^|]|%[^\n]", 
                       type_str, rt->source, rt->target, fcgi_str, vars_str);

        if (n >= 4) {
            // Bersihkan spasi di sekitar string
            trim_whitespace(type_str); 
            trim_whitespace(rt->source); 
            trim_whitespace(rt->target); 
            trim_whitespace(fcgi_str);

            // Tentukan tipe rute (QUERY string atau PATH based)
            rt->type = (strcmp(type_str, "QUERY") == 0) ? RT_QUERY : 
                       (strcmp(type_str, "PATH") == 0) ? RT_PATH : RT_NONE;
            
            // Mapping tipe backend FastCGI
            if (strcmp(fcgi_str, "FCGI_PY") == 0) rt->fcgi_type = FCGI_PY;
            else if (strcmp(fcgi_str, "FCGI_RS") == 0) rt->fcgi_type = FCGI_RS;
            else if (strcmp(fcgi_str, "FCGI_PHP") == 0) rt->fcgi_type = FCGI_PHP;
            else rt->fcgi_type = FCGI_PHP;

            // Parsing variabel tambahan jika tipe rute adalah QUERY (format: [var1,var2])
            rt->var_count = 0;
            if (n == 5 && rt->type == RT_QUERY) {
                char *start = strchr(vars_str, '[');
                char *end = strchr(vars_str, ']');
                if (start && end) {
                    *end = '\0';
                    char *token = strtok(start + 1, ",");
                    while (token && rt->var_count < 10) {
                        trim_whitespace(token);
                        strncpy(rt->var_names[rt->var_count++], token, 31);
                        token = strtok(NULL, ",");
                    }
                }
            }
            temp_count++;
        }
    }
    
    // Update jumlah rute secara "Atomic" di akhir proses
    vh->total_routes = temp_count;
    
    fclose(fp);
}
