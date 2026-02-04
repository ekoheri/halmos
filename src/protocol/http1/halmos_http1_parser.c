#include "halmos_http1_parser.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_config.h"  // Di sini variabel 'config' sudah ada (extern)
#include "halmos_log.h"     // Di sini variabel 'global_queue' sudah ada (extern)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>    // Wajib buat struct timeval
#include <sys/socket.h>  // Wajib buat setsockopt

// Objek Antrean Global (Pusat Kendali)
TaskQueue global_queue;

void parse_request_line(char *line, RequestHeader *req);

bool parse_http_request(const char *raw_data, size_t total_received, RequestHeader *req) {
    // 1. Cari batas Header (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    if (!header_end) return false;

    size_t header_len = header_end - raw_data;
    char *header_tmp = strndup(raw_data, header_len);

    // 2. Parse Baris Pertama
    char *saveptr;
    char *line = strtok_r(header_tmp, "\r\n", &saveptr);
    if (line) {
        parse_request_line(line, req);
    }

    // 3. Loop Parsing Header Lainnya (Content-Length, Type, Connection)
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            req->content_length = atol(line + 15);
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            req->content_type = strdup(line + 13);
            trim_whitespace(req->content_type); // Gunakan fungsi dari utils.c
        } else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (strcasestr(line, "keep-alive")) req->is_keep_alive = true;
            else if (strcasestr(line, "close")) req->is_keep_alive = false;
        } else if (strncasecmp(line, "Cookie:", 7) == 0) {
            const char *val = line + 7;
            while (*val == ' ') val++; // Lewati spasi setelah titik dua
            
            // Simpan isinya (misal: "user=eko; session=123")
            req->cookie_data = strdup(val); 
        } else if (strncasecmp(line, "Host:", 5) == 0) {
            char *host_val = line + 5;
            while (*host_val == ' ') host_val++; // Trim spasi depan
            req->host = strdup(host_val);  // Simpan ke struct
        }
    }//end while
    free(header_tmp);

    // 4. Salin Body
    if (req->content_length > 0) {
        char *body_start = (char *)header_end + 4;
        size_t bytes_in_buffer = total_received - (body_start - raw_data);
        
        req->body_data = malloc(req->content_length + 1);
        if (req->body_data) {
            size_t to_copy = (bytes_in_buffer > (size_t)req->content_length) 
                             ? (size_t)req->content_length : bytes_in_buffer;
            
            memcpy(req->body_data, body_start, to_copy);
            req->body_length = to_copy;
            
            // Safety null terminator untuk data teks
            ((char*)req->body_data)[to_copy] = '\0';
        }
    }

    // 5. Jika Multipart, panggil modul multipart
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        parse_multipart_body(req);
    }

    // 6. Final Summary Log (Satu baris cukup!)
    if (req->is_valid) {
        write_log("[REQUEST] %s %s | Host: %s | Body: %ld bytes | Keep-Alive: %s",
                  req->method, 
                  req->uri, 
                  req->host ? req->host : "unknown", 
                  req->content_length,
                  req->is_keep_alive ? "YES" : "NO");
    } else {
        write_log("[REQUEST] Malformed request detected from: %s", req->host ? req->host : "unknown");
    }
    return req->is_valid;
}

void free_request_header(RequestHeader *req) {
    if (req->uri) free(req->uri);
    if (req->host) free(req->host);
    if (req->query_string) free(req->query_string);
    if (req->content_type) free(req->content_type);
    if (req->body_data) free(req->body_data);
    if (req->cookie_data) {
        free(req->cookie_data);
        req->cookie_data = NULL;
    }
    
    // Bersihkan bagian multipart jika ada
    if (req->parts) {
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].name) free(req->parts[i].name);
            if (req->parts[i].filename) free(req->parts[i].filename);
            if (req->parts[i].data) free(req->parts[i].data);
            if (req->parts[i].content_type) free(req->parts[i].content_type);
        }
        free(req->parts);
    }
}

void parse_request_line(char *line, RequestHeader *req) {
    char *m = strtok(line, " ");
    char *u = strtok(NULL, " ");
    char *v = strtok(NULL, " ");

    if (m && u) {
        strncpy(req->method, m, sizeof(req->method) - 1);
        if (v) strncpy(req->http_version, v, sizeof(req->http_version) - 1);

        // 1. Pisahkan Query String jika ada
        char *q = strchr(u, '?');
        if (q) {
            req->query_string = strdup(q + 1);
            url_decode(req->query_string); // Gunakan fungsi dari utils.c
            *q = '\0';
        } else {
            req->query_string = strdup("");
        }

        // 2. Simpan URI dan Decode
        req->uri = strdup((u[0] == '/' && u[1] == '\0') ? "index.html" : u);
        url_decode(req->uri); 
        
        req->is_valid = true;
    }
}