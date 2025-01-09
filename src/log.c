#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "../include/log.h"
#include "../include/config.h"

extern Config config;

/*void create_log_directory() {
    struct stat st;
    if (stat(config.log_directory, &st) != 0) { // Cek apakah folder log sudah ada
        if (mkdir(config.log_directory, 0700) != 0) { // Buat folder log jika belum ada
            fprintf(stderr, "Warning: Failed to create log directory: %s\n", strerror(errno));
            // Tidak keluar program, biarkan log tetap berjalan atau lakukan penanganan lebih lanjut
        }
    }
}*/

void write_log(const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Format tanggal untuk nama file log
    char log_filename[100];
    snprintf(log_filename, sizeof(log_filename), "%s%04d-%02d-%02d.log",
         LOG_DIR, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday); // Simpan di dalam folder logs

    FILE *log_file = fopen(log_filename, "a"); // Buka file log untuk menambahkan
    if (log_file != NULL) {
        // Format timestamp dalam format yang sesuai
        char timestamp[25];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
        
        // Tulis timestamp ke file log
        fprintf(log_file, "[%s] ", timestamp);

        // Mengelola variadic arguments
        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args); // Tulis pesan dengan format variadic ke file log
        va_end(args);

        fprintf(log_file, "\n"); // Tambahkan newline otomatis
        fclose(log_file); // Tutup file
    } else {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
    }
}
