#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include "http_common.h" 
#include "fs_handler.h"
#include "log.h"

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

const char *get_mime_type(const char *file) {
    // Cari extension dari file
    const char *dot = strrchr(file, '.');

    // Jika tidak ditemukan extension atau MIME type yang cocok,
    // kembalikan "text/html" sebagai default
    if (!dot) return "text/html";
    else if (strcmp(dot, ".html") == 0) return "text/html";
    else if (strcmp(dot, ".css") == 0) return "text/css";
    else if (strcmp(dot, ".js") == 0) return "application/js";
    else if (strcmp(dot, ".jpg") == 0) return "image/jpeg";
    else if (strcmp(dot, ".png") == 0) return "image/png";
    else if (strcmp(dot, ".gif") == 0) return "image/gif";
    else if (strcmp(dot, ".ico") == 0) return "image/ico";
    else if (strcmp(dot, ".rs") == 0) return "text/plain"; // Jangan dieksekusi
    else if (strcmp(dot, ".py") == 0) return "text/plain"; // Jangan dieksekusi
    else return "text/html";  // Default MIME type
} //end get_mime_type

// Fungsi untuk menyimpan file yang di-upload dari browser
// Fungsi ini di dunia pemrograman web nyata, nyaris tidak digunakan
// karena biasanya penanganan file langsung dilakukan oleh backend PHP/Rust
bool save_uploaded_file(MultipartPart *part, const char *destination_folder) {
    if (!part || !part->filename || !part->data) return false;

    char full_path[PATH_MAX];
    // Pastikan folder tujuan ada dan aman
    snprintf(full_path, sizeof(full_path), "%s/%s", destination_folder, part->filename);

    FILE *fp = fopen(full_path, "wb");
    if (!fp) {
        write_log("Gagal membuka file untuk penulisan: %s", full_path);
        return false;
    }

    size_t written = fwrite(part->data, 1, part->data_len, fp);
    fclose(fp);

    if (written == part->data_len) {
        write_log("File berhasil disimpan: %s (%zu bytes)", full_path, written);
        return true;
    }

    return false;
}
