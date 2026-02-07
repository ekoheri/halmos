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
    // 1. Cari batas Header (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    if (!header_end) return false;

    // Suntik NULL sementara agar strtok_r tidak kebablasan ke body
    *header_end = '\0'; 

    char *saveptr_line;   // Pointer untuk iterasi baris (\r\n)
    char *saveptr_word;   // Pointer untuk iterasi kata (spasi) di Request Line

    // 2. Parse Baris Pertama (Request Line)
    char *line = strtok_r(raw_data, "\r\n", &saveptr_line);
    if (line) {
        // Pakai saveptr_word supaya tidak mengganggu saveptr_line
        char *m = strtok_r(line, " ", &saveptr_word);
        char *u = strtok_r(NULL, " ", &saveptr_word);
        char *v = strtok_r(NULL, " ", &saveptr_word);

        if (m && u) {
            // Copy aman dengan paksa null-terminator
            strncpy(req->method, m, sizeof(req->method) - 1);
            req->method[sizeof(req->method) - 1] = '\0';

            if (v) {
                strncpy(req->http_version, v, sizeof(req->http_version) - 1);
                req->http_version[sizeof(req->http_version) - 1] = '\0';
            }

            // Pisahkan Query String secara In-place
            char *q = strchr(u, '?');
            if (q) {
                *q = '\0'; 
                req->query_string = q + 1;
            } else {
                req->query_string = ""; 
            }
            
            req->uri = u; 
            req->is_valid = true;

            write_log("Request: Method=%s, Resource=%s, Version=%s", 
                      req->method, req->uri, req->http_version);
        }
    }

    // 3. Loop Parsing Header Fields
    // Lanjutkan iterasi baris menggunakan saveptr_line yang tadi
    while ((line = strtok_r(NULL, "\r\n", &saveptr_line)) != NULL) {
        char *colon = strchr(line, ':');
        if (!colon) continue;

        *colon = '\0'; 
        char *value = fast_trim(colon + 1);

        if (strcasecmp(line, "Host") == 0) {
            req->host = value;
        } else if (strcasecmp(line, "Content-Type") == 0) {
            req->content_type = value;
        } else if (strcasecmp(line, "Content-Length") == 0) {
            req->content_length = atoi(value);
        } else if (strcasecmp(line, "Cookie") == 0) {
            req->cookie_data = value;
        } else if (strcasecmp(line, "Connection") == 0) {
            req->is_keep_alive = (strcasestr(value, "keep-alive") != NULL);
        }
    }

    // 4. Set Body Data (Zero-Copy)
    // Kembalikan alamat awal body
    char *body_start = header_end + 4;
    req->body_data = body_start; 
    req->body_length = total_received - (body_start - raw_data);

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

