#ifndef HALMOS_HTTP_UTILS_H
#define HALMOS_HTTP_UTILS_H

#include <stddef.h>

typedef struct {
    const char *ext;
    const char *type;
} MimeMap;

/**
 * Mendekode karakter persen (%) dan tanda plus (+) pada URL/Query String.
 */
void url_decode(char *src);

/**
 * Menghapus spasi dan karakter newline di akhir string.
 */
void trim_right(char *s);

/**
 * Menghapus spasi, tab, dan newline di awal dan akhir string.
 */
void trim_whitespace(char *str);

/**
 * Mendapatkan string waktu saat ini dalam format HTTP (GMT) + Milidetik.
 * Note: Pemanggil harus melakukan free() pada string hasil.
 */
char *get_time_string();

int has_extension(const char *uri, const char *path_info, const char *ext);

const char* get_active_root(const char *incoming_host);

char *sanitize_path(const char *root, const char *uri);

const char *get_mime_type(const char *file);

const char* get_status_text(int code);

#endif