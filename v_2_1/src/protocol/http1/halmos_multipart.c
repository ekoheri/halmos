#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"

/**********************************************
 * Ini hanya fungsi cadangan saja untuk menangani upload file besar
 * Di dunia pemrograman nyata, fungsi ini nyaris tidak digunakan
 * karena yang menangani multipart biasanya adalah backend (PHP/Rust)
 * Hanya jika diperlukan, maka fungsi ini disediakan
***********************************************/
void parse_multipart_body(RequestHeader *req) {
    if (!req->content_type || !req->body_data || req->body_length == 0) return;

    // 1. Ekstrak Boundary dari Content-Type
    char *boundary_ptr = strstr(req->content_type, "boundary=");
    if (!boundary_ptr) return;
    
    char boundary[256];
    snprintf(boundary, sizeof(boundary), "--%s", boundary_ptr + 9);
    size_t boundary_len = strlen(boundary);

    char *current_pos = (char *)req->body_data;
    size_t remaining_len = req->body_length;

    // Alokasi awal untuk 10 parts (bisa di-realloc jika kurang)
    req->parts = malloc(sizeof(MultipartPart) * 10);
    req->parts_count = 0;

    while (remaining_len > boundary_len) {
        // Cari posisi boundary
        char *part_start = memmem(current_pos, remaining_len, boundary, boundary_len);
        if (!part_start) break;

        // Header part dimulai setelah boundary + \r\n
        char *header_start = part_start + boundary_len + 2;
        
        // Cari akhir dari header part (\r\n\r\n)
        char *header_end = memmem(header_start, remaining_len - (header_start - (char*)req->body_data), "\r\n\r\n", 4);
        if (!header_end) break;

        // --- INI BAGIAN BARU (Taruh tepat di sini) ---
        // Cek apakah laci sudah penuh (0-9 sudah terisi, sekarang mau isi yang ke-10)
        if (req->parts_count >= 10 && req->parts_count % 10 == 0) {
            size_t new_size = sizeof(MultipartPart) * (req->parts_count + 10);
            MultipartPart *temp = realloc(req->parts, new_size);
            if (!temp) {
                //write_log("Security: Gagal menambah kapasitas Multipart (Out of Memory)");
                break; 
            }
            req->parts = temp;
        }
        // --------------------------------------------

        MultipartPart *p = &req->parts[req->parts_count];
        memset(p, 0, sizeof(MultipartPart));

        // 2. Ekstrak 'name' dan 'filename' dari header part
        char *h_buf = strndup(header_start, header_end - header_start);
        char *n_ptr = strstr(h_buf, "name=\"");
        if (n_ptr) {
            char *n_end = strchr(n_ptr + 6, '\"');
            if (n_end) p->name = strndup(n_ptr + 6, n_end - (n_ptr + 6));
        }
        char *f_ptr = strstr(h_buf, "filename=\"");
        if (f_ptr) {
            char *f_end = strchr(f_ptr + 10, '\"');
            if (f_end) p->filename = strndup(f_ptr + 10, f_end - (f_ptr + 10));
        }
        free(h_buf);

        // 3. Tentukan letak DATA
        char *data_start = header_end + 4;
        
        // Cari boundary berikutnya untuk menentukan akhir data ini
        char *next_boundary = memmem(data_start, remaining_len - (data_start - (char*)req->body_data), boundary, boundary_len);
        
        if (next_boundary) {
            // data_len adalah jarak antara data_start dan boundary berikutnya (dikurangi \r\n)
            // 1. Hitung panjang data asli (tanpa \r\n sebelum boundary)
            p->data_len = (size_t)((next_boundary - 2) - data_start);

            // 2. KUNCI: Alokasikan data_len + 1 (untuk null terminator)
            p->data = malloc(p->data_len + 1);
            
            if (p->data) {
                // 3. Salin hanya data aslinya (sejauh data_len)
                memcpy(p->data, data_start, p->data_len);
                
                // 4. Tambahkan terminator di byte terakhir yang kita pesan tadi
                // Ini menjaga agar p->data tetap aman jika diakses sebagai string
                ((char*)p->data)[p->data_len] = '\0';
            }
            
            req->parts_count++;
            
            // Geser posisi pembacaan
            remaining_len -= (next_boundary - current_pos);
            current_pos = next_boundary;
        } else {
            break;
        }
    }
}

void free_multipart_parts(MultipartPart *parts, int count) {
    if (!parts) return;
    for (int i = 0; i < count; i++) {
        if (parts[i].name) free(parts[i].name);
        if (parts[i].filename) free(parts[i].filename);
        if (parts[i].data) free(parts[i].data);
        if (parts[i].content_type) free(parts[i].content_type);
    }
    free(parts);
}