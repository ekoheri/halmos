#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <stddef.h>

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

#endif