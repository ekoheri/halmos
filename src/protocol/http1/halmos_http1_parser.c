#include "halmos_http1_parser.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_config.h"
#include "halmos_log.h"
#include "halmos_route.h"


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

bool parse_http_request(char *raw_data, size_t total_received, RequestHeader *req) {
    bool saved_tls = req->is_tls;
    // 0. RESET: Bersihkan struct agar tidak ada sisa data dari request sebelumnya
    memset(req, 0, sizeof(RequestHeader));
    req->is_tls = saved_tls;
    
    req->is_keep_alive = true;

    // 1. CARI BATAS HEADER (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    //if (!header_end) return false;
    if (!header_end) {
        //fprintf(stderr, "[DEBUG-PARSE-ERR] Header end not found!\n");
        return false;
    }
    char *line_start = raw_data;
    char *line_end = strstr(line_start, "\r\n");
    if (!line_end || line_end > header_end) return false;

    // --- PARSE REQUEST LINE (METHOD URI VERSION) ---
    char *m_end = strchr(line_start, ' ');
    if (m_end && m_end < line_end) {
        // 1. Ambil Method (GET, POST, dll)
        size_t m_len = m_end - line_start;
        if (m_len < sizeof(req->method)) {
            memcpy(req->method, line_start, m_len);
            req->method[m_len] = '\0';
        }

        char *u_start = m_end + 1;
        char *u_end = strchr(u_start, ' ');

        if (u_end && u_end < line_end) {
            // 2. Ambil HTTP Version dulu (sebelum u_end ditebas)
            char *v_start = u_end + 1;
            size_t v_len = line_end - v_start;
            if (v_len < sizeof(req->http_version)) {
                memcpy(req->http_version, v_start, v_len);
                req->http_version[v_len] = '\0';
            }

            // 3. Isolasi URI (Tebas spasi akhir)
            *u_end = '\0'; 

            // --- DEBUG URI AWAL ---

            // 4. Pisahkan Query String
            char *q = strchr(u_start, '?');
            if (q) { 
                *q = '\0'; 
                req->query_string = q + 1; 
            } else {
                req->query_string = NULL;
            }

            // --- ANALISIS STRUKTUR PATH (ZERO-COPY) ---
            req->directory = u_start; // Default ke root URI
            req->uri = u_start;       // Default URI adalah u_start
            req->path_info = NULL;

            char *last_dot = strrchr(u_start, '.');
            if (last_dot) {
                // Mundur cari slash terakhir sebelum titik
                char *file_sep = last_dot;
                while (file_sep > u_start && *file_sep != '/') {
                    file_sep--;
                }

                if (file_sep >= u_start) {
                    // Cari jika ada path_info (slash setelah titik)
                    char *p_info = strchr(last_dot, '/');
                    if (p_info) {
                        req->path_info = p_info;
                    }
                    char *file_sep = last_dot;
                    while (file_sep > u_start && *file_sep != '/') {
                        file_sep--;
                    }
                }
            } else {
                // Kasus tanpa titik: Bisa jadi folder atau Clean URL
                // Kita biarkan req->uri = u_start
            }
            req->is_valid = true;
        }
    }

    // 2 [ INJECT TABLE ROUTER ] 

    if (req->is_valid) {
        // Cari di tabel apakah ada rute yang cocok (misal: /dhe-sedang)
        RouteTable *match = match_route(req->uri);

        if (match != NULL) {
            char t_uri[128] = {0}, t_query[256] = {0}, t_path[128] = {0};
            
            // 1. Olah rute ke buffer lokal (misal: /dhe-sedang jadi /test_dhe.php)
            apply_route_logic(match, req->uri, t_uri, t_query, t_path);
            
            // 2. Gabungkan query user jika ada
            if (req->query_string && strlen(req->query_string) > 0) {
                if (strlen(t_query) > 0) strcat(t_query, "&");
                strcat(t_query, req->query_string);
            }

            // 3. UPDATE DATA DI STRUCT
            // Simpan hasil rakitan ke route_result milik struct
            int offset = 0;

            // Update req->uri
            req->uri = &req->route_result[offset];
            strcpy(req->uri, t_uri);
            offset += strlen(t_uri) + 1;

            // 2. SINKRONISASI UNTUK SISTEM UTAMA (PENTING!)
            // Agar SCRIPT_FILENAME di FastCGI otomatis mengarah ke file yang benar
            req->directory = req->uri;

            // Update req->query_string
            req->query_string = &req->route_result[offset];
            strcpy(req->query_string, t_query);
            offset += strlen(t_query) + 1;

            // --- SINKRONISASI URI & PATH_INFO ---
            offset = 0;
            req->uri = &req->route_result[offset];
            
            // 1. Copy URI Target (misal: /test_directory/index.php)
            strcpy(req->uri, t_uri);
            size_t uri_len = strlen(t_uri);
            
            // 2. Tempelkan Path Info tepat di belakangnya tanpa jeda \0
            // Format memori: [/test_directory/index.php][/eko/malang/123] \0
            if (strlen(t_path) > 0) {
                // Pointing path_info ke alamat tepat setelah URI berakhir
                req->path_info = req->uri + uri_len; 
                
                // strcat akan menimpa \0 milik t_uri dan menutupnya di akhir t_path
                strcat(req->uri, t_path);
            } else {
                req->path_info = NULL; 
            }

            req->backend_type = match->fcgi_type;
        } else {
            // Jika rute tidak ditemukan (NULL), default ke PHP
            // URI dan Query tetap menunjuk ke raw_data (Zero-Copy murni)
            req->backend_type = FCGI_PHP;
        }
    }
    
    // 3. PARSE HEADERS
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
                // FIX BUG: Digunakan strtol agar tidak overflow/negatif
                req->content_length = strtol(val, NULL, 10);
                if (req->content_length < 0) req->content_length = 0;
            }
            else if (strcasecmp(key, "Cookie") == 0) req->cookie_data = val;
            else if (strcasecmp(key, "Connection") == 0) {
                // UPDATE: Cek "close" secara eksplisit
                if (strcasestr(val, "close")) {
                    req->is_keep_alive = false;
                } else if (strcasestr(val, "keep-alive")) {
                    req->is_keep_alive = true;
                }
            }
        }
        p = next_line + 2;
    }

    if (req->is_valid) {
        write_log("[HTTP] %s %s (Host: %s)", req->method, req->uri, req->host ? req->host : "unknown");
    }

    // 4. SET BODY DATA (Penting untuk POST)
    char *body_start = header_end + 4;
    req->body_data = body_start; 
    
    // Proteksi perhitungan body_length
    if (total_received >= (size_t)(body_start - raw_data)) {
        req->body_length = total_received - (body_start - raw_data);
    } else {
        req->body_length = 0;
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
    // 5. LOGIKA MULTIPART
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        // Panggil fungsi multipart dari halmos_multipart.c
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
}

