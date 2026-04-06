#ifndef HALMOS_HTTP_ROUTE_H
#define HALMOS_HTTP_ROUTE_H

/* --- Konfigurasi Maksimal --- */
#define MAX_ROUTES 100
#define MAX_VAR_COUNT 10
#define MAX_VAR_NAME_LEN 32

// --- PERBAIKAN DI SINI ---
struct VHostEntry;                  // Forward declaration tag
typedef struct VHostEntry VHostEntry; // Beri nama alias agar VHostEntry *vh valid

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

struct VHostEntry; // Forward declaration asli

/* --- Global Variable untuk Tabel Rute --- */
// Disimpan secara eksternal agar bisa diakses di main program
/* --- Global Variable --- */
//extern RouteTable g_routes[MAX_ROUTES];
//extern int g_total_routes;
extern const char *route_config_filename;

/* --- Prototipe Fungsi Eksternal --- */

/**
 * Fungsi Auto Reload yang dipanggil di event loop.
 * Mengecek mtime file setiap 5 detik.
 */
void http_route_auto_reload();

/**
 * Mencocokkan URI request dengan tabel rute.
 * Digunakan untuk mencari baris mana yang cocok di memory.
 */
RouteTable* http_route_match(VHostEntry *vh, const char *uri);

/**
 * Melakukan transformasi URL.
 * Memecah URI user menjadi Script Target, Query String, atau Path Info.
 */
void http_route_apply_logic(RouteTable *match, const char *original_uri, char *out_target, char *out_query, char *out_path_info);

#endif