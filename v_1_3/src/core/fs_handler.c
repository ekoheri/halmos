#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include "http_common.h" 
#include "fs_handler.h"
#include "log.h"
#include "config.h"

typedef struct {
    const char *ext;
    const char *type;
} MimeMap;

extern Config config;

/************************************
 * Fungsi untuk membaca daftar virtual host
*************************************/
const char* get_active_root(const char *incoming_host) {
    // 1. Bersihkan incoming_host dari port jika ada (misal: localhost:8080 -> localhost)
    char clean_host[256];
    strncpy(clean_host, incoming_host, sizeof(clean_host));
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
