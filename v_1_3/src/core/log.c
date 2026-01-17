#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "../include/core/log.h"
#include "../include/core/config.h"

extern Config config;

/***************************************
 * Fungsi ini berguna untuk menuliskan kejadian di server ke log
 * Log disimpan di folder /var/log/halmos
 * Anda bisa melihat per hari
****************************************/

void write_log(const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Format tanggal untuk nama file log
    char log_filename[100];

    // Simpan di dalam folder logs (/var/log/halmos/)
    snprintf(log_filename, sizeof(log_filename), "%s%04d-%02d-%02d.log",
         LOG_DIR, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday); 

    // Buka file log untuk menambahkan
    FILE *log_file = fopen(log_filename, "a"); 
    if (log_file != NULL) {
        // Format timestamp dalam format yang sesuai
        char timestamp[25];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
        
        // Tulis timestamp ke file log
        fprintf(log_file, "[%s] ", timestamp);

        // Mengelola variadic arguments
        va_list args;
        va_start(args, format);

        // Tulis pesan dengan format variadic ke file log
        vfprintf(log_file, format, args); 
        va_end(args);

        // Tambahkan newline otomatis
        fprintf(log_file, "\n"); 
        fclose(log_file); // Tutup file
    } else {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
    }
}
