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

static void http2_response_send_complex_header(HTTP2Session *session, HTTP2Stream *stream, char *raw_headers, unsigned char flags);

/*
Public Function
*/

void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream) {
    RequestHeader *req = &stream->http1_compat;

    // =================================================================
    // 1. INTERSEPSI HANDSHAKE WEBSOCKET HTTP/2 (RFC 8441)
    // =================================================================
    if (req->is_upgrade == true) {
        //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u: Intercepting WebSocket upgrade request.\n", stream->stream_id);
        unsigned char ws_ok_payload[1] = { 0x88 }; // Indexed Header for Status 200
        
        pthread_mutex_lock(&session->streams_lock);
        http2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, ws_ok_payload, 1);
        pthread_mutex_unlock(&session->streams_lock);
        return; 
    }
    
    // =================================================================
    // 2. IDENTIFIKASI BACKEND (PHP / RUST / PYTHON)
    // =================================================================
    int backend_type = -1; 
    if (has_extension(req->uri, req->path_info, ".php")) { 
        backend_type = 0; 
    } 
    else if (has_extension(req->uri, req->path_info, config.rust.ext)) { 
        backend_type = 1; 
    } 
    else if (has_extension(req->uri, req->path_info, config.python.ext)) { 
        backend_type = 2; 
    }

    // MULTIPART PARSER FOR NON-FCGI
    if (backend_type == -1 && req->method[0] != '\0' && strcasecmp(req->method, "POST") == 0 && 
        req->content_type && strstr(req->content_type, "multipart/form-data")) {
        http2_multipart_parse(req);
    }

    // =================================================================
    // 3. JALUR FASTCGI BACKEND
    // =================================================================
    if (backend_type != -1) {
        //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: Routing to FastCGI backend (type: %d, URI: %s)\n", 
        //        stream->stream_id, backend_type, req->uri ? req->uri : "NULL");
        
        char *backend_data = NULL;
        ssize_t data_len = fcgi_api_request_http2(req, backend_type, req->body_data, req->content_length, &backend_data);
        
        if (data_len > 0 && backend_data) {
            char *divider = strstr(backend_data, "\r\n\r\n");
            
            if (divider) {
                *divider = '\0'; 
                char *raw_headers = backend_data;
                char *body_data = divider + 4;
                size_t body_len = data_len - (body_data - backend_data);

                //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: FastCGI Header & Body Split (Body Len: %zu bytes)\n", 
                //        stream->stream_id, body_len);

                // 1. Kirim HEADERS Frame (END_HEADERS flag = 0x04)
                http2_response_send_complex_header(session, stream, raw_headers, 0x04);

                // 2. Kirim DATA Frame (END_STREAM flag = true)
                http2_response_send_data(session, stream, (unsigned char*)body_data, body_len, true);
            } else {
                //fprintf(stderr, "[H2-FCGI][DEBUG] Stream %u: FastCGI Headers-only response.\n", stream->stream_id);
                http2_response_send_complex_header(session, stream, backend_data, 0x05); // END_STREAM | END_HEADERS
                http2_response_send_data(session, stream, NULL, 0, true);
            }
            
            free(backend_data);

            stream->state = 4; // State CLOSED
            //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u (FastCGI) finished successfully.\n", stream->stream_id);
            return; 
        } else {
            //fprintf(stderr, "[H2-FCGI][ERR] Stream %u: FastCGI returned empty response / 502.\n", stream->stream_id);
            http2_response_send_header(session, stream, 502);
            http2_response_send_data(session, stream, "Bad Gateway", 11, true);
            stream->state = 4; 
            return;
        }
    }

    // =================================================================
    // 4. JALUR FILE STATIS
    // =================================================================
    VHostEntry *vh = (VHostEntry *)req->vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    //fprintf(stderr, "[H2-STATIC][DEBUG] Stream %u Request: URI=%s, Resolved Path=%s\n", 
    //        stream->stream_id, req->uri ? req->uri : "(null)", safe_path ? safe_path : "(null)");

    if (!safe_path || stat(safe_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        //fprintf(stderr, "[H2-STATIC][WARN] Stream %u: File not found or path invalid (%s)\n", 
        //        stream->stream_id, safe_path ? safe_path : "NULL");
        http2_response_send_header(session, stream, 404);
        http2_response_send_data(session, stream, "Not Found", 9, true);
        if (safe_path) free(safe_path);
        stream->state = 4;
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        //fprintf(stderr, "[H2-STATIC][ERR] Stream %u: Failed to open descriptor for %s\n", stream->stream_id, safe_path);
        http2_response_send_header(session, stream, 403);
        http2_response_send_data(session, stream, "Forbidden", 9, true);
        stream->state = 4;
    } else {
        // 1. Kirim HANYA response HEADERS (200 OK)
        http2_response_send_header(session, stream, 200);

        size_t file_size = (size_t)st.st_size;

        if (file_size == 0) {
            //fprintf(stderr, "[H2-STATIC][DEBUG] Stream %u: 0-byte static file. Sending END_STREAM.\n", stream->stream_id);
            http2_response_send_data(session, stream, NULL, 0, true);
            close(fd);
            stream->state = 4; // CLOSED
        } else {
            // 2. Jika ada isi file, DAFTARKAN FD KE STREAM (JANGAN DIBACA DI SINI!)
            pthread_mutex_lock(&session->streams_lock);
            stream->file_fd = fd;
            stream->file_size = file_size;
            stream->file_offset = 0;
            stream->is_sending_file = true;
            pthread_mutex_unlock(&session->streams_lock);

            //fprintf(stderr, "[H2-STATIC][ASYNC] Stream %u: File FD %d registered for async flushing (%zu bytes).\n", 
            //        stream->stream_id, fd, file_size);
        }
    }
    
    if (safe_path) free(safe_path);
    //fprintf(stderr, "[H2-BRIDGE][DEBUG] Stream %u static file setup complete.\n", stream->stream_id);
}

void http2_response_send_header(HTTP2Session *session, HTTP2Stream *stream, int status_code) {
    unsigned char hpack_buf[512];
    int pos = 0;

    // 1. HPACK Status Mapping (Indexed Header Field - RFC 7541 Sec 6.1)
    switch(status_code) {
        case 200: hpack_buf[pos++] = 0x88; break; // Index 8 (:status: 200)
        case 204: hpack_buf[pos++] = 0x89; break; // Index 9 (:status: 204)
        case 304: hpack_buf[pos++] = 0x8B; break; // Index 11 (:status: 304)
        case 400: hpack_buf[pos++] = 0x8C; break; // Index 12 (:status: 400)
        case 404: hpack_buf[pos++] = 0x8D; break; // Index 13 (:status: 404)
        case 500: hpack_buf[pos++] = 0x8E; break; // Index 14 (:status: 500)
        default: {
            // Literal Header Field without Indexing - Indexed Name (:status = Index 8)
            hpack_buf[pos++] = 0x08; 
            char s_str[10];
            int s_len = snprintf(s_str, sizeof(s_str), "%d", status_code);
            hpack_buf[pos++] = (unsigned char)(s_len & 0x7F); // Raw string length (bit H=0)
            memcpy(hpack_buf + pos, s_str, (size_t)s_len);
            pos += s_len;
            break;
        }
    }

    // 2. MIME Type Detection
    const char *mime_to_use = NULL;
    if (stream->http1_compat.uri) {
        if (strstr(stream->http1_compat.uri, ".php")) {
            mime_to_use = "text/html";
        } else {
            mime_to_use = get_mime_type(stream->http1_compat.uri);
        }
    }
    if (!mime_to_use) mime_to_use = "text/plain"; 

    // 3. HPACK Content-Type 
    // Menggunakan Literal Header WITHOUT Indexing (Index Name 31 = content-type)
    // 0x0F berarti: Prefix 0000 (without indexing) + Index 15 (0x0F) -> 31 dalam 4-bit prefix
    hpack_buf[pos++] = 0x0F; 
    hpack_buf[pos++] = 0x10; // Value index 31 - 15 = 16 (0x10) di HPACK integer encoding

    size_t mlen = strlen(mime_to_use);
    if (mlen > 127) mlen = 127;
    
    hpack_buf[pos++] = (unsigned char)(mlen & 0x7F); // Bit H = 0 (No Huffman)
    memcpy(&hpack_buf[pos], mime_to_use, mlen);
    pos += mlen;

    //fprintf(stderr, "[H2-HEADER][DEBUG] Stream %u: Sending status %d header frame (%d bytes, MIME: %s)\n", 
    //        stream->stream_id, status_code, pos, mime_to_use);

    pthread_mutex_lock(&session->streams_lock);
    http2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, hpack_buf, (uint32_t)pos);
    pthread_mutex_unlock(&session->streams_lock);
}

void http2_response_send_header_kompleks(HTTP2Session *session, HTTP2Stream *stream, int status_code) {
    unsigned char hpack_buf[512];
    int pos = 0;

    // 1. HPACK Status Mapping (Indexed Header Field - RFC 7541 Sec 6.1)
    switch(status_code) {
        case 200: hpack_buf[pos++] = 0x88; break; // Index 8 (:status: 200)
        case 204: hpack_buf[pos++] = 0x89; break; // Index 9 (:status: 204)
        case 304: hpack_buf[pos++] = 0x8B; break; // Index 11 (:status: 304)
        case 400: hpack_buf[pos++] = 0x8C; break; // Index 12 (:status: 400)
        case 404: hpack_buf[pos++] = 0x8D; break; // Index 13 (:status: 404)
        case 500: hpack_buf[pos++] = 0x8E; break; // Index 14 (:status: 500)
        default: {
            // Literal Header Field without Indexing - Indexed Name (:status = Index 8)
            hpack_buf[pos++] = 0x08; 
            char s_str[10];
            int s_len = snprintf(s_str, sizeof(s_str), "%d", status_code);
            hpack_buf[pos++] = (unsigned char)(s_len & 0x7F); // Raw string length (bit H=0)
            memcpy(hpack_buf + pos, s_str, (size_t)s_len);
            pos += s_len;
            break;
        }
    }

    // 2. MIME Type Detection
    const char *mime_to_use = NULL;
    if (stream->http1_compat.uri) {
        if (strstr(stream->http1_compat.uri, ".php")) {
            mime_to_use = "text/html";
        } else {
            mime_to_use = get_mime_type(stream->http1_compat.uri);
        }
    }
    if (!mime_to_use) mime_to_use = "text/plain"; 

    // 3. HPACK Content-Type 
    // Menggunakan Literal Header WITHOUT Indexing (Index Name 31 = content-type)
    // 0x0F berarti: Prefix 0000 (without indexing) + Index 15 (0x0F) -> 31 dalam 4-bit prefix
    hpack_buf[pos++] = 0x0F; 
    hpack_buf[pos++] = 0x10; // Value index 31 - 15 = 16 (0x10) di HPACK integer encoding

    size_t mlen = strlen(mime_to_use);
    if (mlen > 127) mlen = 127;
    
    hpack_buf[pos++] = (unsigned char)(mlen & 0x7F); // Bit H = 0 (No Huffman)
    memcpy(&hpack_buf[pos], mime_to_use, mlen);
    pos += mlen;

    //fprintf(stderr, "[H2-HEADER][DEBUG] Stream %u: Sending status %d header frame (%d bytes, MIME: %s)\n", 
    //        stream->stream_id, status_code, pos, mime_to_use);

    pthread_mutex_lock(&session->streams_lock);
    http2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, hpack_buf, (uint32_t)pos);
    pthread_mutex_unlock(&session->streams_lock);
}

void http2_response_send_data(HTTP2Session *session, HTTP2Stream *stream, const void *data, size_t len, bool is_end) {
    const unsigned char *ptr = (const unsigned char *)data;
    size_t remaining = len;
    uint32_t max_frame = 16384; 
    bool end_stream_sent = false;

    pthread_mutex_lock(&session->streams_lock); 

    // Skenario A: Data Kosong (0 bytes) tapi is_end = true
    if (len == 0) {
        if (is_end) {
            //fprintf(stderr, "[H2-DATA][DEBUG] Stream %u: Sending empty DATA frame with END_STREAM (0x01)\n", stream->stream_id);
            http2_send_frame(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
            stream->state = 4; // State Closed
        }
        pthread_mutex_unlock(&session->streams_lock);
        return;
    }

    // Skenario B: Kirim Data Chunking 16KB
    while (remaining > 0) {
        uint32_t chunk = (remaining > (size_t)max_frame) ? max_frame : (uint32_t)remaining;
        uint8_t flags = 0x00;

        if (is_end && remaining == chunk) {
            flags = 0x01; // END_STREAM Flag
            end_stream_sent = true;
        }

        //fprintf(stderr, "[H2-DATA][TRACE] Stream %u: Sending DATA frame | Chunk: %u bytes | Remaining: %zu | Flags: 0x%02X\n", 
        //        stream->stream_id, chunk, remaining - chunk, flags);

        http2_send_frame(session->fd, session->is_tls, 0x00, flags, stream->stream_id, ptr, chunk);

        ptr += chunk;
        remaining -= chunk;
    }

    // Backup safety check: Hanya kirim empty frame jika loop di atas BELUM mengirimkan flag END_STREAM
    if (is_end && !end_stream_sent) {
        //fprintf(stderr, "[H2-DATA][WARN] Stream %u: Sending fallback empty END_STREAM frame\n", stream->stream_id);
        http2_send_frame(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
    }

    if (is_end) {
        stream->state = 4; // Set state stream ke CLOSED
        //fprintf(stderr, "[H2-DATA][DEBUG] Stream %u state set to CLOSED (4)\n", stream->stream_id);
    }

    pthread_mutex_unlock(&session->streams_lock);
}

/*
Private Function Internal Helper
*/

void http2_response_send_complex_header(HTTP2Session *session, HTTP2Stream *stream, char *raw_headers, unsigned char flags) {
    if (!raw_headers) {
        //fprintf(stderr, "[H2-COMPLEX-HEADER][ERR] Stream %u: raw_headers is NULL!\n", stream->stream_id);
        return;
    }

    // Alokasi dinamis 16KB di heap untuk mengantisipasi header FastCGI/PHP yang sangat besar (Set-Cookie, JWT, dll)
    size_t buf_capacity = 16384;
    unsigned char *hpack_buf = (unsigned char *)malloc(buf_capacity);
    if (!hpack_buf) {
        //fprintf(stderr, "[H2-COMPLEX-HEADER][ERR] Stream %u: Failed to allocate HPACK buffer!\n", stream->stream_id);
        return;
    }

    int pos = 0;
    int final_status = 200;
    bool has_location = false;

    // 1. DETEKSI HEADER "Status:"
    char *status_ptr = strcasestr(raw_headers, "Status:");
    if (status_ptr) {
        char *p = status_ptr + 7;
        while (*p == ' ' || *p == '\t') p++;
        int parsed = atoi(p);
        if (parsed > 0) {
            final_status = parsed;
        }
        //fprintf(stderr, "[H2-COMPLEX-HEADER][DEBUG] Stream %u: Found 'Status:' header -> Parsed Status: %d\n", 
        //        stream->stream_id, parsed);
    }

    // 2. DETEKSI HEADER "Location:"
    if (strcasestr(raw_headers, "Location:") != NULL) {
        has_location = true;
        //fprintf(stderr, "[H2-COMPLEX-HEADER][DEBUG] Stream %u: Found 'Location:' header.\n", stream->stream_id);
    }

    // 3. KOREKSI STATUS UNTUK REDIRECT
    if (has_location && (final_status == 200 || final_status == 304 || final_status == 0)) {
        //(stderr, "[H2-COMPLEX-HEADER][DEBUG] Stream %u: Override status %d -> 302 (Location header exists)\n", 
        //        stream->stream_id, final_status);
        final_status = 302;
    }

    // 4. ENCODE PSEUDO-HEADER :status KE HPACK BUFFER
    switch (final_status) {
        case 200: hpack_buf[pos++] = 0x88; break; 
        case 204: hpack_buf[pos++] = 0x89; break; 
        case 304: hpack_buf[pos++] = 0x8B; break; 
        case 400: hpack_buf[pos++] = 0x8C; break; 
        case 404: hpack_buf[pos++] = 0x8D; break; 
        case 500: hpack_buf[pos++] = 0x8E; break; 
        default: {
            hpack_buf[pos++] = 0x08; // Name Index 8 (:status)
            char s_str[10];
            int s_len = snprintf(s_str, sizeof(s_str), "%d", final_status);
            
            // Encode length (7-bit prefix HPACK)
            if (s_len < 127) {
                hpack_buf[pos++] = (unsigned char)s_len;
            } else {
                hpack_buf[pos++] = 0x7F; // Fallback bound
            }
            memcpy(hpack_buf + pos, s_str, (size_t)s_len);
            pos += s_len;
            break;
        }
    }

    // 5. PARSING BARIS DEMI BARIS HEADER DARI FASTCGI
    char *saveptr;
    char *headers_copy = strdup(raw_headers);
    if (!headers_copy) {
        free(hpack_buf);
        return;
    }

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

            // Filter pseudo-header "status"
            if (strcmp(key, "status") == 0) {
                line = strtok_r(NULL, "\r\n", &saveptr);
                continue;
            }

            size_t klen = strlen(key);
            size_t vlen = strlen(value);

            // Safety Guard: Reallocate jika mendekati batas kapasitas buffer
            if ((size_t)pos + klen + vlen + 16 > buf_capacity) {
                buf_capacity *= 2;
                unsigned char *new_buf = (unsigned char *)realloc(hpack_buf, buf_capacity);
                if (!new_buf) {
                    //fprintf(stderr, "[H2-COMPLEX-HEADER][ERR] Stream %u: Realloc failed! Truncating headers.\n", stream->stream_id);
                    break;
                }
                hpack_buf = new_buf;
            }

            // HPACK Encoding: Literal without Indexing (0x00)
            hpack_buf[pos++] = 0x00; 
            
            // Encode Key Length (HPACK 7-bit prefix integer)
            if (klen < 127) {
                hpack_buf[pos++] = (unsigned char)klen;
            } else {
                // Sederhanakan truncate jika key anomali > 127 char
                klen = 127;
                hpack_buf[pos++] = 0x7F;
            }
            memcpy(hpack_buf + pos, key, klen);
            pos += (int)klen;
            
            // Encode Value Length (FIX: Mengatasi truncation pada value > 127 bytes seperti Cookie)
            if (vlen < 127) {
                hpack_buf[pos++] = (unsigned char)vlen;
            } else {
                // Untuk string > 127, HPACK menggunakan multi-byte integer encoding
                hpack_buf[pos++] = 0x7F;
                size_t rem = vlen - 127;
                while (rem >= 128) {
                    hpack_buf[pos++] = (unsigned char)((rem & 0x7F) | 0x80);
                    rem >>= 7;
                }
                hpack_buf[pos++] = (unsigned char)rem;
            }
            memcpy(hpack_buf + pos, value, vlen);
            pos += (int)vlen;

            //fprintf(stderr, "[H2-COMPLEX-HEADER][TRACE] Stream %u Header: %s: %s (KLen: %zu, VLen: %zu)\n", 
            //        stream->stream_id, key, value, klen, vlen);
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    free(headers_copy);

    //fprintf(stderr, "[H2-COMPLEX-HEADER][DEBUG] Stream %u: Encoded HPACK Total Size: %d bytes | Flags: 0x%02X\n", 
    //        stream->stream_id, pos, flags);
        
    pthread_mutex_lock(&session->streams_lock);
    http2_send_frame(session->fd, session->is_tls, 0x01, flags, stream->stream_id, hpack_buf, (uint32_t)pos);
    pthread_mutex_unlock(&session->streams_lock);

    free(hpack_buf);
}
