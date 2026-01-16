#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

// Kita include http.h di file .c saja, bukan di .h
// Ini aman karena tidak akan menyebabkan circular include
#include "../include/protocols/common/http_common.h" 
#include "../include/core/fs_handler.h"
#include "../include/core/log.h"

char *sanitize_path(const char *root, const char *uri) {
    char full_path[PATH_MAX];
    char resolved_path[PATH_MAX];

    // 1. Gabungkan root dan uri mentah
    snprintf(full_path, sizeof(full_path), "%s/%s", root, uri);

    // 2. Gunakan realpath() untuk menyelesaikan ".." dan "."
    // realpath akan mengubah "/var/www/html/../etc/passwd" menjadi "/etc/passwd"
    if (realpath(full_path, resolved_path) == NULL) {
        return NULL; // Path tidak valid atau file tidak ada
    }

    // 3. KUNCI KEAMANAN: Pastikan resolved_path masih dimulai dengan root
    // Jika tidak, berarti user mencoba melompat keluar dari folder web
    if (strncmp(root, resolved_path, strlen(root)) != 0) {
        return NULL; // Upaya bypass terdeteksi!
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
    else return "text/html";  // Default MIME type
} //end get_mime_type

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
