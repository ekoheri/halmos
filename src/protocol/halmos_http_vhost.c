#include "halmos_http_vhost.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

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

static void _vhost_load_single_route_file(VHostEntry *vh, const char *path) {
    //fprintf(stderr, "[DEBUG] _vhost_load_single_route_file: %s\n", path);
    if (!vh) { 
        //fprintf(stderr, "[DEBUG] ERROR: vh is NULL!\n"); 
        return; 
    }

    FILE *fp = fopen(path, "r");
    if (!fp) { 
        //fprintf(stderr, "[DEBUG] Gagal buka file: %s (errno: %d)\n", path, errno); 
        return; 
    }

    vh->total_routes = 0;
    char line[512];
    
    while (fgets(line, sizeof(line), fp) && vh->total_routes < MAX_ROUTES) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        //fprintf(stderr, "[DEBUG] Parsing baris %d: %s", vh->total_routes, line);
        RouteTable *rt = &vh->routes[vh->total_routes];
        char type_str[16], fcgi_str[16], vars_str[256] = {0};
        
        int n = sscanf(line, "%[^|]|%[^|]|%[^|]|%[^|]|%[^\n]", 
                       type_str, rt->source, rt->target, fcgi_str, vars_str);

        if (n >= 4) {
            trim_whitespace(type_str); trim_whitespace(rt->source); 
            trim_whitespace(rt->target); trim_whitespace(fcgi_str);

            rt->type = (strcmp(type_str, "QUERY") == 0) ? RT_QUERY : 
                       (strcmp(type_str, "PATH") == 0) ? RT_PATH : RT_NONE;
            
            if (strcmp(fcgi_str, "FCGI_PY") == 0) rt->fcgi_type = FCGI_PY;
            else if (strcmp(fcgi_str, "FCGI_RS") == 0) rt->fcgi_type = FCGI_RS;
            else rt->fcgi_type = FCGI_PHP;

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
            vh->total_routes++;
        }
    }
    fclose(fp);
}

void http_vhost_reload_routes() {
    // Hapus static timer dulu buat debug supaya setiap dipanggil pasti jalan
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