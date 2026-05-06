#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_http2_core.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void http_multipart_parse_body(RequestHeader *req) {
    if (!req->content_type || !req->body_data || req->body_length == 0) return;

    // 1. Ekstrak Boundary
    char *boundary_ptr = strstr(req->content_type, "boundary=");
    if (!boundary_ptr) {
        write_log_error("[HTTP] Multipart boundary missing from %s", req->client_ip);
        return;
    }
    
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
                write_log_error("[MEM] Failed to realloc multipart parts for %s", req->client_ip);
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

            // LOG SETIAP PART YANG BERHASIL DI-PARSE
            write_log("[UPLOAD] Part #%d parsed: name=\"%s\", file=\"%s\" (%zu bytes)", 
                      req->parts_count + 1, 
                      p->name ? p->name : "none", 
                      p->filename ? p->filename : "none", 
                      p->data_len);
                      
            remaining_len -= (next_boundary - current_pos);
            current_pos = next_boundary;
            req->parts_count++;
        } else {
            break;
        }
    }
}

void http_multipart_free_parts(MultipartPart *parts, int count) {
    if (!parts) return;
    for (int i = 0; i < count; i++) {
        // Bebaskan hasil strdup (Milik sendiri)
        if (parts[i].name) free(parts[i].name);
        if (parts[i].filename) free(parts[i].filename);
        
        // parts[i].data JANGAN di-free karena itu Zero-Copy (Nempel buffer utama)
    }
    free(parts); // Bebaskan array-nya
}

/**
 * http2_multipart_parse
 * Parser khusus untuk HTTP/2 yang lebih toleran terhadap struktur frame-based.
 */
void http2_multipart_parse(RequestHeader *req) {
    if (!req->content_type || !req->body_data || req->body_length == 0) return;

    // 1. Ekstraksi Boundary dari Header Content-Type
    char *boundary_ptr = strstr(req->content_type, "boundary=");
    if (!boundary_ptr) return;

    char boundary[256];
    memset(boundary, 0, sizeof(boundary));
    char *src = boundary_ptr + 9;
    int b_idx = 0;
    boundary[b_idx++] = '-';
    boundary[b_idx++] = '-';
    while (src[b_idx-2] && src[b_idx-2] != ' ' && src[b_idx-2] != ';' && src[b_idx-2] != '\r' && b_idx < 250) {
        boundary[b_idx] = src[b_idx-2];
        b_idx++;
    }
    int b_len = b_idx;

    char *current_pos = (char *)req->body_data;
    size_t remaining_len = req->body_length;

    // Alokasi awal untuk part (Sesuai gaya Halmos: 10 part awal)
    req->parts = calloc(10, sizeof(MultipartPart));
    req->parts_count = 0;

    while (remaining_len > (size_t)b_len) {
        char *part_start = memmem(current_pos, remaining_len, boundary, b_len);
        if (!part_start) break;

        if (req->parts_count > 0 && req->parts_count % 10 == 0) {
            MultipartPart *tmp = realloc(req->parts, sizeof(MultipartPart) * (req->parts_count + 10));
            if (!tmp) return; 
            req->parts = tmp;
            // SARAN: Bersihkan memori baru hasil realloc
            memset(&req->parts[req->parts_count], 0, sizeof(MultipartPart) * 10);
        }

        char *header_start = part_start + b_len;
        while (header_start < (char*)req->body_data + req->body_length && (*header_start == '\r' || *header_start == '\n')) {
            header_start++;
        }

        char *header_end = memmem(header_start, req->body_length - (header_start - (char*)req->body_data), "\r\n\r\n", 4);
        if (!header_end) break;

        MultipartPart *p = &req->parts[req->parts_count];

        // Parsing name=" dan filename=" (Logika internal strstr tetap sama)
        char *n_ptr = strstr(header_start, "name=\"");
        if (n_ptr && n_ptr < header_end) {
            char *n_end = strchr(n_ptr + 6, '\"');
            if (n_end) {
                size_t n_len = n_end - (n_ptr + 6);
                p->name = malloc(n_len + 1);
                memcpy(p->name, n_ptr + 6, n_len);
                p->name[n_len] = '\0';
            }
        }

        char *f_ptr = strstr(header_start, "filename=\"");
        if (f_ptr && f_ptr < header_end) {
            char *f_end = strchr(f_ptr + 10, '\"');
            if (f_end) {
                size_t f_len = f_end - (f_ptr + 10);
                p->filename = malloc(f_len + 1);
                memcpy(p->filename, f_ptr + 10, f_len);
                p->filename[f_len] = '\0';
            }
        }

        p->data = header_end + 4;
        size_t search_len = req->body_length - ((char*)p->data - (char*)req->body_data);
        char *next_boundary = memmem(p->data, search_len, boundary, b_len);
        
        if (next_boundary) {
            if (next_boundary >= (char*)p->data + 2 && *(next_boundary - 2) == '\r') {
                p->data_len = (size_t)((next_boundary - 2) - (char*)p->data);
            } else {
                p->data_len = (size_t)(next_boundary - (char*)p->data);
            }
            remaining_len = req->body_length - (next_boundary - (char*)req->body_data);
            current_pos = next_boundary;
            req->parts_count++;
        } else {
            break;
        }
    }
}
