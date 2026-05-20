#include "halmos_http1_response.h"
#include "halmos_http2_response.h"
#include "halmos_http2_manager.h"
#include "halmos_http2_parser.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_http_multipart.h"
#include "halmos_fcgi.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>      // Untuk open, O_RDONLY
#include <sys/stat.h>   // Untuk stat, struct stat, S_ISDIR
#include <limits.h>     // Untuk PATH_MAX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>     // Untuk AF_UNIX
#include <sys/types.h>  // Wajib untuk ssize_t
#include <stddef.h>     // Untuk size_t
#include <ctype.h>
#include <time.h>

static void http2_response_send_complex_header(HTTP2Session *session, HTTP2Stream *stream, char *raw_headers);

static void http2_stream_detach_and_destroy(HTTP2Session *session, uint32_t stream_id);

/*
Public Function
*/
void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream) {
    RequestHeader *req = &stream->http1_compat;

    // =================================================================
    // INTERSEPSI HANDSHAKE WEBSOCKET HTTP/2 (RFC 8441)
    // =================================================================
    if (req->is_upgrade == true) {
        //fprintf(stderr, "[H2-WS] Menangani Handshake WebSocket pada Stream %u dengan URI: %s\n", 
        //        stream->stream_id, req->uri ? req->uri : "NULL");

        // Kirim :status: 200 OK ke browser untuk menyetujui pembukaan tunnel biner.
        // PERINGATAN: Jangan gunakan http2_response_send_header(session, stream, 200) 
        // jika fungsi tersebut otomatis mengirimkan flag END_STREAM (0x01). 
        // Jalur WebSocket HTTP/2 HARUS tetap terbuka (END_STREAM = false).
        
        // Kita rakit manual HPACK minimalis untuk ":status: 200" (Index 8 di Static Table)
        unsigned char ws_ok_payload[1] = { 0x88 }; // 0x88 adalah Indexed Header untuk Status 200
        
        // Kirim HEADERS Frame (Type 0x01) dengan Flag END_HEADERS (0x04) saja. NO END_STREAM!
        http2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, ws_ok_payload, 1);
        
        //fprintf(stderr, "[H2-WS] Handshake 200 OK sukses dikirim ke Stream %u. Tunnel aktif!\n", stream->stream_id);
        
        // Jangan ubah stream->state menjadi 4 (HALF_CLOSED/CLOSED). Biarkan tetap terbuka (OPEN).
        return; 
    }
    // =================================================================
    
    // 1. IDENTIFIKASI BACKEND
    int backend_type = -1; 
    if (has_extension(req->uri, req->path_info, ".php")) { 
        backend_type = 0; // PHP
    } 
    else if (has_extension(req->uri, req->path_info, config.rust.ext)) { 
        backend_type = 1; // Rust
    } 
    else if (has_extension(req->uri, req->path_info, config.python.ext)) { 
        backend_type = 2; // Python
    }

    // 2. LOGIKA MULTIPART PARSER
    if (backend_type == -1 && req->method[0] != '\0' && strcasecmp(req->method, "POST") == 0 && 
        req->content_type && strstr(req->content_type, "multipart/form-data")) {
        //fprintf(stderr, "[TRACE-H2] Parsing multipart data\n");
        http2_multipart_parse(req);
    }

    //fprintf(stderr, "[DEBUG-H2] URI: %s | Backend: %d\n", req->uri ? req->uri : "NULL", backend_type);

    // 3. JALUR FASTCGI (PHP, DLL)
    if (backend_type != -1) {
        char *backend_data = NULL;
        ssize_t data_len = fcgi_api_request_http2(req, backend_type, req->body_data, req->content_length, &backend_data);
        
        if (data_len > 0 && backend_data) {
            char *divider = strstr(backend_data, "\r\n\r\n");
            
            if (divider) {
                *divider = '\0'; // Pisahkan Header dan Body
                char *body_start = divider + 4;
                
                // --- DETEKSI STATUS CODE ---
                char *status_ptr = strcasestr(backend_data, "Status:");
                int s_code = status_ptr ? atoi(status_ptr + 7) : 200;
                
                // a. Kirim HEADERS Frame
                http2_response_send_complex_header(session, stream, backend_data);

                // b. Kirim DATA Frame HANYA jika bukan Redirect (3xx)
                if (s_code < 300 || s_code >= 400) {
                    size_t body_len = (size_t)(data_len - (body_start - backend_data));
                    if (body_len > 0) {
                        //fprintf(stderr, "[H2-TRACE] Sending Data Frame, Len: %zu\n", body_len);
                        http2_response_send_data(session, stream, body_start, body_len, true);
                    } else {
                        //fprintf(stderr, "[H2-TRACE] Body empty, sending empty DATA with END_STREAM\n");
                        http2_response_send_data(session, stream, NULL, 0, true);
                    }
                } /*else {
                    fprintf(stderr, "[H2-SUCCESS] Redirect %d handled, stream closed via HEADERS flags.\n", s_code);
                }*/
            } else {
                //fprintf(stderr, "[ERROR-H2] Divider not found in backend data\n");
                http2_response_send_complex_header(session, stream, backend_data);
            }
            free(backend_data);
        } else {
            //fprintf(stderr, "[ERROR-H2] No data from FCGI backend\n");
            http2_response_send_header(session, stream, 502);
            http2_response_send_data(session, stream, "Bad Gateway", 11, true);
        }

        // --- SEBELUM RETURN, ANCURKAN STREAM SECARA TERHORMAT ---
        uint32_t dead_stream_id = stream->stream_id;
        http2_stream_detach_and_destroy(session, dead_stream_id);
        return;
    }

    // 4. JALUR FILE STATIS
    VHostEntry *vh = (VHostEntry *)req->vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    if (!safe_path || stat(safe_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        //fprintf(stderr, "[TRACE-H2] File not found or invalid: %s\n", safe_path ? safe_path : "NULL");
        http2_response_send_header(session, stream, 404);
        http2_response_send_data(session, stream, "Not Found", 9, true);
        if(safe_path) free(safe_path);
        return;
    }

    // 5. KIRIM HEADER FILE STATIS
    //fprintf(stderr, "[TRACE-H2] Serving static file: %s\n", safe_path);
    http2_response_send_header(session, stream, 200);

    // 6. KIRIM DATA FILE STATIS
    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        //fprintf(stderr, "[H2-STATIC-DEBUG] Gagal buka file (403 Forbidden): %s\n", safe_path);
        http2_response_send_data(session, stream, "Forbidden", 9, true);
    } else {
        unsigned char buffer[16384];
        ssize_t n;
        size_t total_sent = 0;
        size_t file_size = (size_t)st.st_size;

        if (file_size == 0) {
            //fprintf(stderr, "[H2-STATIC-DEBUG] File size 0, mengirim data kosong dengan END_STREAM\n");
            http2_response_send_data(session, stream, NULL, 0, true);
        } else {
            // Jalankan read loop dengan is_end = false agar aman dari interupsi chunking
            int chunk_count = 0;
            while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
                chunk_count++;
                total_sent += n;
                bool is_last_byte = (total_sent >= file_size);

                //fprintf(stderr, "[H2-STATIC-DEBUG] Loop Read Loop-%d: n=%zd, total_sent=%zu/%zu, is_last_byte=%s\n", 
                //    chunk_count, n, total_sent, file_size, is_last_byte ? "TRUE" : "FALSE");
                
                http2_response_send_data(session, stream, buffer, (size_t)n, is_last_byte);
            }
            //fprintf(stderr, "[H2-STATIC-DEBUG] Keluar dari loop read(). Total read selesai: %zu bytes\n", total_sent);

            // SAFETY NET: Jika karena alasan tertentu loop read selesai tapi END_STREAM belum terkirim
            // (misalnya ukuran file di disk berubah secara dinamis saat dibaca)
            if (total_sent < file_size) {
                //fprintf(stderr, "[H2-STATIC-WARN] File size mismatch, forcing empty END_STREAM\n");
                http2_response_send_data(session, stream, NULL, 0, true);
            }
        }
        close(fd);
        //fprintf(stderr, "[H2-STATIC-DEBUG] File descriptor closed. Menyerahkan sisa state ke Event Loop Halmos.\n");
        //usleep(10000);
        uint32_t dead_stream_id = stream->stream_id;
        http2_stream_detach_and_destroy(session, dead_stream_id);
    }
    
    if(safe_path) free(safe_path);
    //fprintf(stderr, "[H2-STATIC-DEBUG] Fungsi http2_response_routing_bridge SELESAI (Return).\n");
    return;
}

void http2_response_send_header(HTTP2Session *session, HTTP2Stream *stream, int status_code) {
    unsigned char hpack_buf[512]; // Perbesar sedikit buat jaga-jaga
    int pos = 0;

    // 1. Status Code
    switch(status_code) {
        case 200: hpack_buf[pos++] = 0x88; break; // Index 8
        case 204: hpack_buf[pos++] = 0x89; break; // Index 9
        case 206: hpack_buf[pos++] = 0x8F; break; // Index 15 (Pindahkan ke sini kalau emang butuh)
        case 301: hpack_buf[pos++] = 0x89; break; // HATI-HATI: Index 9 itu 204, 301 itu index 10 (0x8A)
        case 302: hpack_buf[pos++] = 0x8B; break; // Index 11 (0x8B)
        case 304: hpack_buf[pos++] = 0x8C; break; // Index 12
        case 400: hpack_buf[pos++] = 0x8E; break; // Index 14
        case 404: hpack_buf[pos++] = 0x8D; break; // Index 13
        case 500: hpack_buf[pos++] = 0x91; break; // Index 17
        default:  
            // Jangan kasih 206! Kasih literal 200 atau 500
            hpack_buf[pos++] = 0x88; 
            break;
    }

    // 2. Tentukan MIME Type
    const char *mime_to_use;
    if (stream->http1_compat.uri && strstr(stream->http1_compat.uri, ".php")) {
        mime_to_use = "text/html";
    } else {
        mime_to_use = get_mime_type(stream->http1_compat.uri);
    }
    
    if (!mime_to_use) mime_to_use = "text/plain"; 

    // 3. Masukkan ke HPACK (Content-Type)
    // 0x5F = Literal Header Field with Incremental Indexing — Indexed Name (index 31)
    hpack_buf[pos++] = 0x5F; 
    
    size_t mlen = strlen(mime_to_use);
    if (mlen > 255) mlen = 255; // Safety limit
    
    hpack_buf[pos++] = (unsigned char)mlen; 
    memcpy(&hpack_buf[pos], mime_to_use, mlen);
    pos += mlen;

    // 4. KIRIM: Type 0x01 (HEADERS), Flag 0x04 (END_HEADERS)
    http2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, hpack_buf, (uint32_t)pos);
    
    //fprintf(stderr, "[H2-DEBUG] Header sent for %s with mime %s\n", 
    //        stream->http1_compat.uri, mime_to_use);
}

void http2_response_send_data(HTTP2Session *session, HTTP2Stream *stream, const void *data, size_t len, bool is_end) {
    const unsigned char *ptr = (const unsigned char *)data;
    size_t remaining = len;
    uint32_t max_frame = 16384; 
    bool end_stream_sent = false;

    if (len == 0) {
        if (is_end) {
            pthread_mutex_lock(&session->streams_lock); // <-- KUNCI DI SINI
            http2_send_frame(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
            pthread_mutex_unlock(&session->streams_lock);
        }
        return;
    }

    // Kunci mutex sebelum melepas frame ke socket
    pthread_mutex_lock(&session->streams_lock); 
    while (remaining > 0) {
        uint32_t chunk = (remaining > (size_t)max_frame) ? max_frame : (uint32_t)remaining;
        uint8_t flags = 0x00;

        if (is_end && remaining == chunk) {
            flags = 0x01;
            end_stream_sent = true;
        }

        
        http2_send_frame(session->fd, session->is_tls, 0x00, flags, stream->stream_id, ptr, chunk);

        ptr += chunk;
        remaining -= chunk;
    }
    pthread_mutex_unlock(&session->streams_lock);

    if (is_end && !end_stream_sent) {
        pthread_mutex_lock(&session->streams_lock);
        http2_send_frame(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
        pthread_mutex_unlock(&session->streams_lock);
    }
}

/*
Private Function Internal Helper
*/

void http2_response_send_complex_header(HTTP2Session *session, HTTP2Stream *stream, char *raw_headers) {
    unsigned char hpack_buf[4096];
    int pos = 0;
    int final_status = 200;

    //fprintf(stderr, "[TRACE-H2] Entering complex_header for Stream %u\n", stream->stream_id);
    
    // 1. Deteksi Status
    char *status_ptr = strcasestr(raw_headers, "Status:");
    if (status_ptr) {
        char *p = status_ptr + 7;
        while (*p == ' ' || *p == '\t') p++;
        final_status = atoi(p);
    }

    // 2. Encode :status
    if (final_status == 200)      hpack_buf[pos++] = 0x88; // :status: 200
    else if (final_status == 301) hpack_buf[pos++] = 0x8A; // :status: 301
    else if (final_status == 304) hpack_buf[pos++] = 0x8C; // :status: 304 (Indeks asli 12)
    else {
        // Untuk 302 dan lainnya yang tidak ada di tabel statis shortcut 1-byte
        // Kita pakai Indeks 8 (Nama: :status) + Literal Value
        hpack_buf[pos++] = 0x08; 
        char s_str[10];
        int s_len = sprintf(s_str, "%d", final_status);
        hpack_buf[pos++] = (unsigned char)s_len;
        memcpy(hpack_buf + pos, s_str, (size_t)s_len);
        pos += s_len;
    }

    // --- BAGIAN CONTENT-LENGTH 0 DIHAPUS ---
    // Jangan paksa content-length: 0, biarkan PHP yang menentukan.

    // 3. Loop Header Lain
    char *saveptr;
    char *headers_copy = strdup(raw_headers);
    char *line = strtok_r(headers_copy, "\r\n", &saveptr);
    
    while (line != NULL) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *key = line;
            char *value = colon + 1;

            while (isspace((unsigned char)*key)) key++;
            char *v_end = value + strlen(value) - 1;
            while (v_end >= value && isspace((unsigned char)*v_end)) {
                *v_end = '\0';
                v_end--;
            }
            while (isspace((unsigned char)*value)) value++;
            
            for (char *p = key; *p; p++) *p = (char)tolower((unsigned char)*p);

            // Filter status saja, content-length biarkan lewat kalau ada dari PHP
            if (strcmp(key, "status") == 0) {
                line = strtok_r(NULL, "\r\n", &saveptr);
                continue;
            }

            hpack_buf[pos++] = 0x10; 
            size_t klen = strlen(key);
            hpack_buf[pos++] = (unsigned char)klen;
            memcpy(hpack_buf + pos, key, klen);
            pos += (int)klen;
            
            size_t vlen = strlen(value);
            hpack_buf[pos++] = (unsigned char)vlen;
            memcpy(hpack_buf + pos, value, vlen);
            pos += (int)vlen;

            //fprintf(stderr, "[TRACE-H2] Header Encoded -> %s: %s (Len: %zu)\n", key, value, vlen);
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    free(headers_copy);

    // 4. Hex Dump & Kirim
    /*fprintf(stderr, "[DEBUG-HPACK-HEX] ");
    for (int i = 0; i < pos; i++) fprintf(stderr, "%02X ", hpack_buf[i]);
    fprintf(stderr, "\n");*/

    // Flag END_HEADERS (0x04) saja. END_STREAM nanti di DATA frame.
    unsigned char flags = (final_status >= 300 && final_status < 400) ? 0x05 : 0x04;
    
    //fprintf(stderr, "[H2-SEND-TRACE] Final Status: %d, Using Flags: 0x%02X\n", final_status, flags);
            
    http2_send_frame(session->fd, session->is_tls, 0x01, flags, stream->stream_id, hpack_buf, (uint32_t)pos);
    
    //fprintf(stderr, "[TRACE-H2] complex_header DONE for Stream %u\n", stream->stream_id);
}

void http2_stream_detach_and_destroy(HTTP2Session *session, uint32_t stream_id) {
    uint32_t bucket = get_bucket_fibonacci(stream_id);
    
    pthread_mutex_lock(&session->streams_lock);
    
    HTTP2Stream *prev = NULL;
    HTTP2Stream *curr = session->streams_hash[bucket];
    
    while (curr != NULL) {
        if (curr->stream_id == stream_id) {
            // Cabut node dari Linked List di dalam Bucket Hash
            if (prev == NULL) {
                session->streams_hash[bucket] = curr->node_next;
            } else {
                prev->node_next = curr->node_next;
            }
            session->active_stream_count--;
            break;
        }
        prev = curr;
        curr = curr->node_next;
    }
    
    pthread_mutex_unlock(&session->streams_lock);
    
    // Setelah dicabut dengan aman dari jangkauan event loop utama,
    // barulah kita bebaskan memorinya agar tidak tersentuh oleh cleanup GOAWAY!
    if (curr) {
        http2_parser_free_memory(curr);
        free(curr);
    }
}