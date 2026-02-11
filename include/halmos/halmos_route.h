#ifndef HALMOS_ROUTE_H
#define HALMOS_ROUTE_H

/* --- Konfigurasi Maksimal --- */
#define MAX_ROUTES 100
#define MAX_VAR_COUNT 10
#define MAX_VAR_NAME_LEN 32

typedef enum {
    RT_NONE, 
    RT_QUERY, 
    RT_PATH
} RouteType;

typedef enum {
    FCGI_PHP, 
    FCGI_PY, 
    FCGI_RS
} FcgiBackend;

typedef struct {
    RouteType type;
    char source[64];
    char target[128];
    FcgiBackend fcgi_type;
    char var_names[10][32]; // Kapasitas 10 variabel @32 char
    int var_count;
} RouteTable;

/* --- Global Variable untuk Tabel Rute --- */
// Disimpan secara eksternal agar bisa diakses di main program
/* --- Global Variable --- */
extern RouteTable g_routes[MAX_ROUTES];
extern int g_total_routes;
extern const char *route_config_filename;

/* --- Prototipe Fungsi Eksternal --- */

/**
 * Fungsi Auto Reload yang dipanggil di event loop.
 * Mengecek mtime file setiap 5 detik.
 */
void halmos_router_auto_reload();

/**
 * Membaca file konfigurasi (Internal, tapi bisa dipanggil manual jika perlu).
 */
void load_routes();

/**
 * Mencocokkan URI request dengan tabel rute.
 * Digunakan untuk mencari baris mana yang cocok di memory.
 */
RouteTable* match_route(const char *uri);

/**
 * Melakukan transformasi URL.
 * Memecah URI user menjadi Script Target, Query String, atau Path Info.
 */
void apply_route_logic(RouteTable *match, const char *original_uri, char *out_target, char *out_query, char *out_path_info);

/**
 * Helper Utility
 */
void trim_util(char *str);

#endif