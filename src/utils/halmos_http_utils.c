#include "halmos_http_utils.h"
#include "halmos_global.h"
#include "halmos_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <sys/sysinfo.h> // untuk info CPU dan RAM

#define PATH_MAX 1024

// Fungsi untuk men-dekode URL
// Contoh : ?nama=Eko+hHeri
// Menjadi : ?nama = Eko Heri
void url_decode(char *src) {
    char *dst = src;
    while (*src) {
        if (*src == '+') {
            // Dalam URL, '+' biasanya berarti spasi
            *dst = ' ';
        } else if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            // Ambil 2 digit hex (misal %20)
            char hex[3] = { src[1], src[2], '\0' };
            *dst = (char)strtol(hex, NULL, 16);
            src += 2;
        } else {
            *dst = *src;
        }
        src++;
        dst++;
    }
    *dst = '\0';
}

// Fungsi untuk menghapus spasi sebelah kanan tulisan
void trim_right(char *s) {
    if (!s) return;
    int len = strlen(s);
    while (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n' || isspace(s[len-1]))) {
        s[len-1] = '\0';
        len--;
    }
}

// Fungsi untuk mengenkode satu pasangan parameter (name-value)
void trim_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == '\t')) {
        str[len - 1] = '\0';
        len--;
    }
}

/****************************************
 * Fungsi untuk mengambil nilai waktu sistem
 * Tanggal, bulan, tahun, jam, menit, detik, milidetik
****************************************/
char *get_time_string() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    // Mengambil waktu dalam format struct tm (GMT)
    struct tm *tm_info = localtime(&tv.tv_sec);

    // Alokasikan buffer untuk waktu dan milidetik
    char *buf = (char *)malloc(64);
    if (!buf) return NULL; 

    // Format waktu tanpa milidetik terlebih dahulu
    strftime(buf, 64, "%a, %d %b %Y %H:%M:%S", tm_info);
    
    // Tambahkan milidetik ke string
    int millis = tv.tv_usec / 1000;
    snprintf(buf + strlen(buf), 64 - strlen(buf), ".%03d GMT", millis);

    return buf;
}

// Fungsi pembantu: Cek apakah string berakhir dengan suffix tertentu
// Lebih kencang dan akurat daripada strstr()
int has_extension(const char *uri, const char *ext) {
    size_t len_uri = strlen(uri);
    size_t len_ext = strlen(ext);
    if (len_uri < len_ext) return 0;
    return (strcasecmp(uri + len_uri - len_ext, ext) == 0);
}

/************************************
 * Fungsi untuk membaca daftar virtual host
*************************************/
const char* get_active_root(const char *incoming_host) {
    // 1. Bersihkan incoming_host dari port jika ada (misal: localhost:8080 -> localhost)
    char clean_host[256];
    strncpy(clean_host, incoming_host, sizeof(clean_host) - 1);
    clean_host[sizeof(clean_host) - 1] = '\0';
    
    char *port_ptr = strchr(clean_host, ':');
    if (port_ptr) *port_ptr = '\0';

    // 2. Cari di daftar VHost
    for (int i = 0; i < config.vhost_count; i++) {
        if (strcmp(config.vhosts[i].host, clean_host) == 0) {
            return config.vhosts[i].root;
        }
    }

    // 3. Kalau nggak ada yang cocok, balik ke default_root dari [Storage]
    return config.document_root;
}

char *sanitize_path(const char *root, const char *uri) {
    char full_path[PATH_MAX];
    char resolved_path[PATH_MAX];

    // Gabungkan dengan cerdas: cek apakah uri sudah punya slash
    if (uri[0] == '/') {
        snprintf(full_path, sizeof(full_path), "%s%s", root, uri);
    } else {
        snprintf(full_path, sizeof(full_path), "%s/%s", root, uri);
    }

    if (realpath(full_path, resolved_path) == NULL) {
        // printf("[DEBUG] realpath gagal untuk: %s\n", full_path);
        return NULL;
    }

    // Gunakan realpath juga untuk si ROOT agar perbandingannya 'apple-to-apple'
    char resolved_root[PATH_MAX];
    if (realpath(root, resolved_root) == NULL) return NULL;
    
    size_t root_len = strlen(resolved_root);
    if (strncmp(resolved_root, resolved_path, root_len) != 0) {
        return NULL;
    }

    return strdup(resolved_path);
}

// WAJIB URUT ABJAD buat Binary Search
static MimeMap mime_types[] = {
    {".css",  "text/css"},
    {".gif",  "image/gif"},
    {".html", "text/html"},
    {".ico",  "image/x-icon"},
    {".js",   "text/javascript"}, 
    {".jpg",  "image/jpeg"},
    {".png",  "image/png"},
    {".txt",  "text/plain"}
};

const char *get_mime_type(const char *file) {
    const char *dot = strrchr(file, '.');
    if (!dot) return "text/html";

    // Pake Binary Search (bsearch) bawaan C
    // Kecepatannya O(log n), jauh lebih kenceng dari else-if
    int low = 0, high = sizeof(mime_types) / sizeof(MimeMap) - 1;
    while (low <= high) {
        int mid = (low + high) / 2;
        int res = strcmp(dot, mime_types[mid].ext);
        if (res == 0) return mime_types[mid].type;
        if (res < 0) high = mid - 1;
        else low = mid + 1;
    }

    return "application/octet-stream"; // Default buat file gak dikenal
}