#include "halmos_http1_response.h"
#include "halmos_http2_response.h"
#include "halmos_http2_frame.h"
#include "halmos_http2_stream.h"

#include "halmos_global.h"
#include "halmos_http_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"
#include "halmos_fcgi_pool.h"           // Untuk fungsi fcgi_pool_conn_release

#include <poll.h>                  // Wajib ada untuk POLLIN dan POLLOUT
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>     // Untuk PATH_MAX
#include <sys/socket.h>
#include <sys/un.h>     // Untuk AF_UNIX
#include <sys/types.h>  // Wajib untuk ssize_t
#include <stddef.h>     // Untuk size_t
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <sys/uio.h>

#define HTTP2_MAX_FRAME_SIZE 16384

/*
Public Function
*/

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
    http2_frame_send(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, hpack_buf, (uint32_t)pos);
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
            http2_frame_send(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
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

        http2_frame_send(session->fd, session->is_tls, 0x00, flags, stream->stream_id, ptr, chunk);

        ptr += chunk;
        remaining -= chunk;
    }

    // Backup safety check: Hanya kirim empty frame jika loop di atas BELUM mengirimkan flag END_STREAM
    if (is_end && !end_stream_sent) {
        //fprintf(stderr, "[H2-DATA][WARN] Stream %u: Sending fallback empty END_STREAM frame\n", stream->stream_id);
        http2_frame_send(session->fd, session->is_tls, 0x00, 0x01, stream->stream_id, NULL, 0);
    }

    if (is_end) {
        stream->state = 4; // Set state stream ke CLOSED
        //fprintf(stderr, "[H2-DATA][DEBUG] Stream %u state set to CLOSED (4)\n", stream->stream_id);
    }

    pthread_mutex_unlock(&session->streams_lock);
}

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
    http2_frame_send(session->fd, session->is_tls, 0x01, flags, stream->stream_id, hpack_buf, (uint32_t)pos);
    pthread_mutex_unlock(&session->streams_lock);

    free(hpack_buf);
}

void http2_response_flush_active_streams(HTTP2Session *session) {
    if (!session) return;
 
    uint32_t active_ids[256];
    int active_count = 0;
    
    // Array untuk menandai jenis aktivitas stream (0 = File, 1 = FastCGI)
    int stream_types[256]; 
 
    // 1. Kumpulkan stream aktif under lock (File statis ATAU FastCGI aktif)
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            bool has_file = (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED);
            bool has_fcgi = curr->is_fcgi_active;

            if ((has_file || has_fcgi) && active_count < 256) {
                active_ids[active_count] = curr->stream_id;
                stream_types[active_count] = has_fcgi ? 1 : 0;
                active_count++;
            }
            curr = curr->node_next;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);
 
    // 2. Iterasi stream aktif
    for (int k = 0; k < active_count; k++) {
        uint32_t target_sid = active_ids[k];
        int s_type = stream_types[k];

        if (s_type == 1) {
            // --- PENANGANAN STREAM FASTCGI ---
            pthread_mutex_lock(&session->streams_lock);
            HTTP2Stream *st = http2_stream_find_unlocked(session, target_sid);
            if (st && st->is_fcgi_active) {
                int fpm_fd = st->fpm_fd;
                int fcgi_state = st->fcgi_state;
                pthread_mutex_unlock(&session->streams_lock);

                // Gunakan poll lokal dengan timeout 0 untuk mengecek event nyata pada fpm_fd
                struct pollfd pfd;
                pfd.fd = fpm_fd;
                pfd.events = POLLIN;
                if (fcgi_state == 0 || fcgi_state == 1 || fcgi_state == 2) {
                    pfd.events |= POLLOUT;
                }
                pfd.revents = 0;

                // Cek status socket secara non-blocking (timeout = 0 ms)
                int ret = poll(&pfd, 1, 0);
                if (ret > 0 && pfd.revents != 0) {
                    // Jalankan FSM step hanya jika benar-benar ada event I/O pada socket FPM
                    int status = fcgi_session_http2_step(session, st, pfd.revents);

                    if (status == FCGI_SES_STATUS_COMPLETED || status == FCGI_SES_STATUS_ERROR) {
                        pthread_mutex_lock(&session->streams_lock);
                        if (st->fpm_fd >= 0) {
                            fcgi_pool_conn_release(st->fpm_fd);
                            st->fpm_fd = -1;
                        }
                        st->is_fcgi_active = false;
                        pthread_mutex_unlock(&session->streams_lock);
                    }
                }
            } else {
                pthread_mutex_unlock(&session->streams_lock);
            }
        } else {
            // --- PENANGANAN STREAM FILE STATIS ---
            int file_fd = -1;
            off_t offset = 0;
            off_t total_size = 0;
            int32_t conn_win = 0;
            int32_t stream_win = 0;
            bool valid = false;
     
            pthread_mutex_lock(&session->streams_lock);
            HTTP2Stream *st = http2_stream_find_unlocked(session, target_sid);
            if (st && st->is_sending_file && st->file_fd >= 0 && st->state != HTTP2_STATE_CLOSED) {
                file_fd = st->file_fd;
                offset = st->file_offset;
                total_size = st->file_size;
                conn_win = session->out_window_size;
                stream_win = st->out_window_size;
                valid = true;
            }
            pthread_mutex_unlock(&session->streams_lock);
     
            if (!valid || file_fd < 0 || offset >= total_size) continue;
            if (conn_win <= 0 || stream_win <= 0) continue;
     
            off_t bytes_remaining = total_size - offset;
            uint32_t max_allowed = HTTP2_MAX_FRAME_SIZE; 
            if ((int32_t)max_allowed > conn_win) max_allowed = (uint32_t)conn_win;
            if ((int32_t)max_allowed > stream_win) max_allowed = (uint32_t)stream_win;
            if ((off_t)max_allowed > bytes_remaining) max_allowed = (uint32_t)bytes_remaining;
     
            if (max_allowed == 0) continue;
     
            unsigned char buf[HTTP2_MAX_FRAME_SIZE];
            ssize_t n_read = pread(file_fd, buf, max_allowed, offset);
     
            if (n_read <= 0) {
                pthread_mutex_lock(&session->streams_lock);
                st = http2_stream_find_unlocked(session, target_sid);
                if (st) {
                    if (st->file_fd >= 0) close(st->file_fd);
                    st->file_fd = -1;
                    st->is_sending_file = false;
                    st->state = HTTP2_STATE_CLOSED;
                }
                pthread_mutex_unlock(&session->streams_lock);
                continue;
            }
     
            uint8_t flags = (offset + n_read >= total_size) ? 0x01 : 0x00;
            http2_frame_send(session->fd, session->is_tls, 0x00, flags, target_sid, buf, (uint32_t)n_read);
     
            pthread_mutex_lock(&session->streams_lock);
            session->out_window_size -= (int32_t)n_read;
            st = http2_stream_find_unlocked(session, target_sid);
            if (st) {
                st->out_window_size -= (int32_t)n_read;
                st->file_offset += n_read;
                if (st->file_offset >= st->file_size) {
                    if (st->file_fd >= 0) close(st->file_fd);
                    st->file_fd = -1;
                    st->is_sending_file = false;
                    st->state = HTTP2_STATE_CLOSED;
                }
            }
            pthread_mutex_unlock(&session->streams_lock);
        }
    }
}

bool http2_response_has_active_streams(HTTP2Session *session) {
    if (!session) return false;
    bool has_active = false;
 
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            bool has_file = (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED);
            bool has_fcgi = curr->is_fcgi_active;

            if (has_file || has_fcgi) {
                has_active = true;
                break;
            }
            curr = curr->node_next;
        }
        if (has_active) break;
    }
    pthread_mutex_unlock(&session->streams_lock);
    
    return has_active;
}
