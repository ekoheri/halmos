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

// Fungsi pembantu untuk trim spasi tanpa alokasi memori
static char* fast_trim(char *s) {
    if (!s) return NULL;
    while (*s == ' ') s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && *end == ' ') end--;
    *(end + 1) = 0;
    return s;
}

bool parse_http_request(char *raw_data, size_t total_received, RequestHeader *req) {
    // 0. RESET: Bersihkan struct agar tidak ada sisa data dari request sebelumnya
    memset(req, 0, sizeof(RequestHeader));

    // 1. CARI BATAS HEADER (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    if (!header_end) return false;

    char *line_start = raw_data;
    char *line_end = strstr(line_start, "\r\n");
    if (!line_end || line_end > header_end) return false;

    // --- PARSE REQUEST LINE (METHOD URI VERSION) ---
    char *m_end = strchr(line_start, ' ');
    if (m_end && m_end < line_end) {
        size_t m_len = m_end - line_start;
        if (m_len < sizeof(req->method)) {
            memcpy(req->method, line_start, m_len);
            req->method[m_len] = '\0';
        }

        char *u_start = m_end + 1;
        char *u_end = strchr(u_start, ' ');
        if (u_end && u_end < line_end) {
            // Parse Versi HTTP
            char *v_start = u_end + 1;
            size_t v_len = line_end - v_start;
            if (v_len < sizeof(req->http_version)) {
                memcpy(req->http_version, v_start, v_len);
                req->http_version[v_len] = '\0';
            }

            // Parse URI & Query String
            *u_end = '\0'; 
            req->uri = u_start;
            char *q = strchr(u_start, '?');
            if (q) {
                *q = '\0'; 
                req->query_string = q + 1;
            } else {
                req->query_string = ""; 
            }
            req->is_valid = true;
        }
    }

    // 2. PARSE HEADERS (Looping aman tanpa strtok_r)
    char *p = line_end + 2; 
    while (p < header_end) {
        char *next_line = strstr(p, "\r\n");
        if (!next_line || next_line > header_end) break;
        
        *next_line = '\0'; 
        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            char *key = p;
            char *val = fast_trim(colon + 1);

            if (strcasecmp(key, "Host") == 0) req->host = val;
            else if (strcasecmp(key, "Content-Type") == 0) req->content_type = val;
            else if (strcasecmp(key, "Content-Length") == 0) {
                // FIX BUG: Gunakan strtol agar tidak overflow/negatif
                req->content_length = strtol(val, NULL, 10);
                if (req->content_length < 0) req->content_length = 0;
            }
            else if (strcasecmp(key, "Cookie") == 0) req->cookie_data = val;
            else if (strcasecmp(key, "Connection") == 0) {
                req->is_keep_alive = (strcasestr(val, "keep-alive") != NULL);
            }
        }
        p = next_line + 2;
    }

    // 3. SET BODY DATA (Penting untuk POST)
    char *body_start = header_end + 4;
    req->body_data = body_start; 
    
    // Proteksi perhitungan body_length
    if (total_received >= (size_t)(body_start - raw_data)) {
        req->body_length = total_received - (body_start - raw_data);
    } else {
        req->body_length = 0;
    }

    // 4. LOGIKA MULTIPART: Aktif kembali!
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        // Panggil fungsi multipart kamu di sini
        parse_multipart_body(req); 
    }

    return req->is_valid;
}

void free_request_header(RequestHeader *req) {
    if (req->parts) {
        free_multipart_parts(req->parts, req->parts_count);
        req->parts = NULL;
        req->parts_count = 0;
    }
    // Field lain (uri, host, query_string) aman, nggak perlu di-free
}

