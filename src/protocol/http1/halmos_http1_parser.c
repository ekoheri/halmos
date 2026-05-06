#include "halmos_http1_parser.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_log.h"

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
// TaskQueue global_queue;

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

bool http1_parser_parse_header(char *raw_data, size_t total_received, RequestHeader *req) {
    bool saved_tls = req->is_tls;
    // RESET: Pastikan vhost_context bersih di awal
    req->vhost_context = NULL;
    req->is_tls = saved_tls;
    req->is_keep_alive = true;

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
            char *v_start = u_end + 1;
            size_t v_len = line_end - v_start;
            if (v_len < sizeof(req->http_version)) {
                memcpy(req->http_version, v_start, v_len);
                req->http_version[v_len] = '\0';
            }

            *u_end = '\0'; 

            char *q = strchr(u_start, '?');
            if (q) { 
                *q = '\0'; 
                req->query_string = q + 1; 
            } else {
                req->query_string = NULL;
            }

            req->directory = u_start; 
            req->uri = u_start;       
            req->path_info = NULL;

            // Analisis titik (extension) tetap sama
            char *last_dot = strrchr(u_start, '.');
            if (last_dot) {
                char *file_sep = last_dot;
                while (file_sep > u_start && *file_sep != '/') file_sep--;

                if (file_sep >= u_start) {
                    char *p_info = strchr(last_dot, '/');
                    if (p_info) req->path_info = p_info;
                }
            }
            req->is_valid = true;
        }
    }

    // 2. PARSE HEADERS (Looping semua baris header)
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

            if (strcasecmp(key, "Host") == 0) {
                req->host = val;
                // --- KRUSIAL: Ambil context VHost di sini ---
                req->vhost_context = (void *)http_vhost_get_context(req->host);
            }
            else if (strcasecmp(key, "Content-Type") == 0) req->content_type = val;
            else if (strcasecmp(key, "Content-Length") == 0) {
                req->content_length = strtol(val, NULL, 10);
                if (req->content_length < 0) req->content_length = 0;
            }
            else if (strcasecmp(key, "Cookie") == 0) req->cookie_data = val;
            else if (strcasecmp(key, "Upgrade") == 0) {
                if (strcasestr(val, "websocket")) req->is_upgrade = true;
            } 
            else if (strcasecmp(key, "Sec-WebSocket-Key") == 0) req->ws.key = val;
            else if (strcasecmp(key, "Connection") == 0) {
                if (strcasestr(val, "Upgrade")) req->is_upgrade = true;
                if (strcasestr(val, "close")) req->is_keep_alive = false;
            } 
            else if (strcasecmp(key, "X-Forwarded-For") == 0 && config.trust_proxy) {
                char *comma = strchr(val, ',');
                if (comma) {
                    size_t ip_len = comma - val;
                    if (ip_len < sizeof(req->client_ip)) {
                        memcpy(req->client_ip, val, ip_len);
                        req->client_ip[ip_len] = '\0';
                        fast_trim(req->client_ip);
                    }
                } else {
                    strncpy(req->client_ip, val, sizeof(req->client_ip) - 1);
                }
            }
        }
        p = next_line + 2;
    }

    // 3. [ INJECT TABLE ROUTER - DYNAMIC LOGIC ] 
    // Dipanggil setelah Host diketahui
    if (req->is_valid) {
        VHostEntry *vh = (VHostEntry *)req->vhost_context;
        RouteTable *match = http_route_match(vh, req->uri);

        if (match != NULL) {
            char t_uri[128] = {0}, t_query[256] = {0}, t_path[128] = {0};
            
            // Terapkan logika dinamis rute kamu
            http_route_apply_logic(match, req->uri, t_uri, t_query, t_path);
            
            if (req->query_string && strlen(req->query_string) > 0) {
                if (strlen(t_query) > 0) strcat(t_query, "&");
                strcat(t_query, req->query_string);
            }

            // Update memori route_result (Zero-copy sync)
            int offset = 0;
            req->uri = &req->route_result[offset];
            strcpy(req->uri, t_uri);
            size_t uri_len = strlen(t_uri);
            offset += uri_len + 1;

            req->query_string = &req->route_result[offset];
            strcpy(req->query_string, t_query);
            offset += strlen(t_query) + 1;

            // Sinkronisasi Path Info
            if (strlen(t_path) > 0) {
                req->path_info = req->uri + uri_len; 
                strcat(req->uri, t_path);
            } else {
                req->path_info = NULL; 
            }
            
            req->directory = req->uri;
            req->backend_type = match->fcgi_type;
        } else {
            req->backend_type = FCGI_PHP;
        }
    }

    // --- SATU BLOK DEBUG TERPUSAT (REKAP PARSER) ---
    /*
    fprintf(stderr, "\n=== [HALMOS PARSER DEBUG RECAP] ===\n");
    fprintf(stderr, " Method      : %s\n", req->method);
    fprintf(stderr, " Final URI   : %s\n", req->uri ? req->uri : "NULL");
    fprintf(stderr, " QueryString : %s\n", req->query_string ? req->query_string : "NULL");
    fprintf(stderr, " Path Info   : %s\n", req->path_info ? req->path_info : "NULL");
    fprintf(stderr, " Host        : %s\n", req->host ? req->host : "NULL");
    fprintf(stderr, " Body Length : %zu\n", req->body_length);
    fprintf(stderr, " Backend     : %s\n", (req->backend_type == FCGI_PHP) ? "PHP-FPM" : "STATIC/OTHER");
    fprintf(stderr, " Keep-Alive  : %s\n", req->is_keep_alive ? "YES" : "NO");
    fprintf(stderr, "====================================\n\n");
    */
    
    // 4. SET BODY DATA (POST/PUT)
    char *body_start = header_end + 4;
    req->body_data = body_start; 
    if (total_received >= (size_t)(body_start - raw_data)) {
        req->body_length = total_received - (body_start - raw_data);
    } else {
        req->body_length = 0;
    }

    if (req->is_valid) {
        write_log("[HTTP1.1] %s %s (Host: %s)", req->method, req->uri, req->host ? req->host : "unknown");
    }

    // 5. LOGIKA MULTIPART
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        http_multipart_parse_body(req); 
    }

    return req->is_valid;
}


void http1_parser_free_memory(RequestHeader *req) {
    if (req->parts) {
        http_multipart_free_parts(req->parts, req->parts_count);
        req->parts = NULL;
        req->parts_count = 0;
    }
}

