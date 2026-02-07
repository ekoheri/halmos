#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"

void parse_multipart_body(RequestHeader *req) {
    if (!req->content_type || !req->body_data || req->body_length == 0) return;

    // 1. Ekstrak Boundary
    char *boundary_ptr = strstr(req->content_type, "boundary=");
    if (!boundary_ptr) return;
    
    char boundary[256];
    int b_len = snprintf(boundary, sizeof(boundary), "--%s", boundary_ptr + 9);

    char *current_pos = (char *)req->body_data;
    size_t remaining_len = req->body_length;

    req->parts = malloc(sizeof(MultipartPart) * 10);
    req->parts_count = 0;

    while (remaining_len > (size_t)b_len) {
        char *part_start = memmem(current_pos, remaining_len, boundary, b_len);
        if (!part_start) break;

        // Cek apakah array parts sudah penuh sebelum memproses part baru
        if (req->parts_count > 0 && req->parts_count % 10 == 0) {
            MultipartPart *tmp = realloc(req->parts, sizeof(MultipartPart) * (req->parts_count + 10));
            if (!tmp) {
                // Jika RAM penuh, kita berhenti parkir part baru tapi 
                // data yang sudah masuk sebelumnya tidak hilang (tidak leak).
                write_log("Error: Gagal realloc memory untuk multipart parts.");
                return; 
            }
            req->parts = tmp;
        }

        char *header_start = part_start + b_len + 2; 
        char *header_end = memmem(header_start, remaining_len - (header_start - current_pos), "\r\n\r\n", 4);
        if (!header_end) break;

        MultipartPart *p = &req->parts[req->parts_count];
        memset(p, 0, sizeof(MultipartPart));

        // --- TEKNIK RESTORE AGAR TIDAK MERUSAK BUFFER FASTCGI ---
        
        // Simpan karakter asli di header_end (\r)
        char orig_header_end = *header_end;
        *header_end = '\0'; 

        // Parsing Name
        char *n_ptr = strstr(header_start, "name=\"");
        if (n_ptr) {
            char *val_start = n_ptr + 6;
            char *n_end = strchr(val_start, '\"');
            if (n_end) {
                // Pinjam buffer: suntik NULL, log/copy, lalu kembalikan
                char orig_n = *n_end;
                *n_end = '\0';
                p->name = strdup(val_start); // Harus di-copy karena buffer asli akan dikembalikan
                *n_end = orig_n;
            }
        }

        // Parsing Filename
        char *f_ptr = strstr(header_start, "filename=\"");
        if (f_ptr) {
            char *val_start = f_ptr + 10;
            char *f_end = strchr(val_start, '\"');
            if (f_end) {
                char orig_f = *f_end;
                *f_end = '\0';
                p->filename = strdup(val_start); // Di-copy agar tetap aman di struct lo
                *f_end = orig_f;
            }
        }

        // Balikkan karakter asli di header_end
        *header_end = orig_header_end;

        // 3. Tentukan Data (Tetap Zero-Copy p->data menunjuk ke buffer asli)
        p->data = header_end + 4;
        
        char *next_boundary = memmem(p->data, req->body_length - ((char*)p->data - (char*)req->body_data), boundary, b_len);
        
        if (next_boundary) {
            //p->data_len = (size_t)((next_boundary - 2) - (char*)p->data);
            if (next_boundary && (next_boundary >= (char*)p->data + 2)) {
                p->data_len = (size_t)((next_boundary - 2) - (char*)p->data);
            } else if (next_boundary) {
                p->data_len = (size_t)(next_boundary - (char*)p->data);
            }
            remaining_len -= (next_boundary - current_pos);
            current_pos = next_boundary;
            req->parts_count++;
        } else {
            break;
        }
    }
}

void free_multipart_parts(MultipartPart *parts, int count) {
    if (!parts) return;
    for (int i = 0; i < count; i++) {
        // Bebaskan hasil strdup (Milik sendiri)
        if (parts[i].name) free(parts[i].name);
        if (parts[i].filename) free(parts[i].filename);
        
        // parts[i].data JANGAN di-free karena itu Zero-Copy (Nempel buffer utama)
    }
    free(parts); // Bebaskan array-nya
}