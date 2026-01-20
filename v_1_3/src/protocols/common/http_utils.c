#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

#include "http_utils.h"

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

