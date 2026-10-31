#include "halmos_http1_response.h"
#include "halmos_http2_response.h"
#include "halmos_http2_frame.h"
#include "halmos_http2_stream.h"

#include "halmos_global.h"
#include "halmos_http_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"

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
        return;
    }

    // Alokasi dinamis 16KB di heap untuk mengantisipasi header FastCGI/PHP yang sangat besar
    size_t buf_capacity = 16384;
    unsigned char *hpack_buf = (unsigned char *)malloc(buf_capacity);
    if (!hpack_buf) {
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
    }

    // 2. DETEKSI HEADER "Location:"
    if (strcasestr(raw_headers, "Location:") != NULL) {
        has_location = true;
    }

    // 3. KOREKSI STATUS UNTUK REDIRECT
    if (has_location && (final_status == 200 || final_status == 304 || final_status == 0)) {
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
            
            if (s_len < 127) {
                hpack_buf[pos++] = (unsigned char)s_len;
            } else {
                hpack_buf[pos++] = 0x7F; 
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

            if (strcmp(key, "status") == 0) {
                line = strtok_r(NULL, "\r\n", &saveptr);
                continue;
            }

            size_t klen = strlen(key);
            size_t vlen = strlen(value);

            if ((size_t)pos + klen + vlen + 16 > buf_capacity) {
                buf_capacity *= 2;
                unsigned char *new_buf = (unsigned char *)realloc(hpack_buf, buf_capacity);
                if (!new_buf) {
                    break;
                }
                hpack_buf = new_buf;
            }

            hpack_buf[pos++] = 0x00; 
            
            if (klen < 127) {
                hpack_buf[pos++] = (unsigned char)klen;
            } else {
                klen = 127;
                hpack_buf[pos++] = 0x7F;
            }
            memcpy(hpack_buf + pos, key, klen);
            pos += (int)klen;
            
            if (vlen < 127) {
                hpack_buf[pos++] = (unsigned char)vlen;
            } else {
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
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    free(headers_copy);

    // TANPA MUTEX LOCK DI SINI KARENA PEMANGGILNYA SUDAH MEMEGANG session->streams_lock
    http2_frame_send(session->fd, session->is_tls, 0x01, flags, stream->stream_id, hpack_buf, (uint32_t)pos);

    free(hpack_buf);
}

/*
void http2_response_flush_active_streams(HTTP2Session *session) {
    if (!session) return;

    uint32_t active_ids[256];
    int active_count = 0;

    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            bool has_file = (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED);
            
            
            //Program awalnya begini!
            //Satu baris program ini, memicu browser muter-muter ketika 
            //mengakses halaman PHP? Kenapa? Karena walaupun statusnya 
            //sudah HTTP2_STATE_CLOSED, masih dianggap has_fcgi= true.
            //Akhirnya server akan terus mengirim data ke browser, 
            //sampai browsernya muter-muter (alias mblenger!)

            //bool has_fcgi = (curr->fcgi_h_ptr > 0 || curr->fcgi_g_ptr > curr->fcgi_g_sent || curr->is_fcgi_active);
            
            //Lalu aku update seperti dibawah, dan browser sudah lancar, walaupin di refresh 100
            
            bool has_fcgi = (curr->state != HTTP2_STATE_CLOSED && 
                 (curr->fcgi_h_ptr > 0 || curr->fcgi_g_ptr > curr->fcgi_g_sent || curr->is_fcgi_active));
            
            // [DEBUG] Pantau stream apa saja yang terdeteksi aktif
            //if (curr->fcgi_h_ptr > 0 || curr->is_fcgi_active) {
            //  fprintf(stderr, "[H2-DEBUG-SCAN] Stream %u | State: %d | has_fcgi: %d | h_ptr: %zu | g_ptr: %zu | g_sent: %zu\n",
            //      curr->stream_id, curr->state, has_fcgi, curr->fcgi_h_ptr, curr->fcgi_g_ptr, curr->fcgi_g_sent);
            //}

            if ((has_file || has_fcgi) && active_count < 256) {
                active_ids[active_count] = curr->stream_id;
                active_count++;
            }
            curr = curr->node_next;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);

    for (int k = 0; k < active_count; k++) {
        uint32_t target_sid = active_ids[k];

        pthread_mutex_lock(&session->streams_lock);
        HTTP2Stream *st = http2_stream_find_unlocked(session, target_sid);
        if (st) {
            
            // --- TAHAP 1: KIRIM HEADER MENGGUNAKAN FLAG 0x04 (END_HEADERS) ---
            if (st->fcgi_h_ptr > 0 && !st->fcgi_header_sent) {
                st->fcgi_header_parsed = true;
                
                //fprintf(stderr, "[H2-FLUSH] Stream %u | Header Size: %zu bytes\n", target_sid, st->fcgi_h_ptr);

                // Flag 0x04 = END_HEADERS wajib agar klien HTTP/2 langsung memproses header
                http2_response_send_complex_header(session, st, (char *)st->fcgi_header_buf, 0x04);
                st->fcgi_header_sent = true;
            }

            // --- TAHAP 2: POMPA BODY DATA ---
            if (st->fcgi_header_sent && (st->fcgi_g_ptr > st->fcgi_g_sent || !st->is_fcgi_active)) {
                size_t bytes_to_send = (st->fcgi_g_ptr > st->fcgi_g_sent) ? (st->fcgi_g_ptr - st->fcgi_g_sent) : 0;
                unsigned char *send_ptr = st->fcgi_gather_buf + st->fcgi_g_sent;

                uint32_t max_allowed = HTTP2_MAX_FRAME_SIZE;
                if ((int32_t)max_allowed > session->out_window_size) max_allowed = (uint32_t)session->out_window_size;
                if ((int32_t)max_allowed > st->out_window_size) max_allowed = (uint32_t)st->out_window_size;
                if (bytes_to_send > max_allowed) bytes_to_send = max_allowed;

                bool is_stream_finished = (!st->is_fcgi_active && (st->fcgi_g_sent + bytes_to_send >= st->fcgi_g_ptr));
                uint8_t flags = is_stream_finished ? 0x01 : 0x00; // 0x01 = END_STREAM

                if (bytes_to_send > 0 || is_stream_finished) {
                    //fprintf(stderr, "[H2-FLUSH] Stream %u | Body Chunk Size: %zu bytes (Total Sent: %zu/%zu)\n", 
                    //        target_sid, bytes_to_send, st->fcgi_g_sent + bytes_to_send, st->fcgi_g_ptr);

                    http2_frame_send(session->fd, session->is_tls, 0x00, flags, target_sid, send_ptr, (uint32_t)bytes_to_send);

                    if (bytes_to_send > 0) {
                        session->out_window_size -= (int32_t)bytes_to_send;
                        st->out_window_size -= (int32_t)bytes_to_send;
                        st->fcgi_g_sent += bytes_to_send;
                    }

                    if (is_stream_finished) {
                       //fprintf(stderr, "[H2-CLOSE] Stream %u selesai sepenuhnya. Menutup stream.\n", target_sid);
                        st->state = HTTP2_STATE_CLOSED;
                        st->is_fcgi_active = false;
                        if (st->fpm_fd >= 0) {
                            close(st->fpm_fd);
                            st->fpm_fd = -1;
                        }
                    }
                }
            }
        }
        pthread_mutex_unlock(&session->streams_lock);

        // --- PENANGANAN B: FILE STATIS (Tetap) ---
        int file_fd = -1;
        off_t offset = 0;
        off_t total_size = 0;
        int32_t conn_win = 0;
        int32_t stream_win = 0;
        bool valid_file = false;
 
        pthread_mutex_lock(&session->streams_lock);
        st = http2_stream_find_unlocked(session, target_sid);
        if (st && st->is_sending_file && st->file_fd >= 0 && st->state != HTTP2_STATE_CLOSED) {
            file_fd = st->file_fd;
            offset = st->file_offset;
            total_size = st->file_size;
            conn_win = session->out_window_size;
            stream_win = st->out_window_size;
            valid_file = true;
        }
        pthread_mutex_unlock(&session->streams_lock);
 
        if (!valid_file || file_fd < 0 || offset >= total_size) continue;
        if (conn_win <= 0 || stream_win <= 0) continue;
 
        off_t bytes_remaining = total_size - offset;
        uint32_t max_allowed_file = HTTP2_MAX_FRAME_SIZE; 
        if ((int32_t)max_allowed_file > conn_win) max_allowed_file = (uint32_t)conn_win;
        if ((int32_t)max_allowed_file > stream_win) max_allowed_file = (uint32_t)stream_win;
        if ((off_t)max_allowed_file > bytes_remaining) max_allowed_file = (uint32_t)bytes_remaining;
 
        if (max_allowed_file == 0) continue;
 
        unsigned char file_buf[HTTP2_MAX_FRAME_SIZE];
        ssize_t n_read = pread(file_fd, file_buf, max_allowed_file, offset);
 
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
 
        uint8_t file_flags = (offset + n_read >= total_size) ? 0x01 : 0x00;
        http2_frame_send(session->fd, session->is_tls, 0x00, file_flags, target_sid, file_buf, (uint32_t)n_read);
 
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
*/

void http2_response_flush_active_streams(HTTP2Session *session) {
    if (!session) return;

    uint32_t active_ids[256];
    int active_count = 0;

    // --- 1. PINDAI STREAM YANG MASIH AKTIF ---
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            bool has_file = (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED);
            
            // Pastikan stream yang sudah CLOSED tidak dibaca lagi
            bool has_fcgi = (curr->state != HTTP2_STATE_CLOSED && 
                 (curr->fcgi_h_ptr > 0 || curr->fcgi_g_ptr > curr->fcgi_g_sent || curr->is_fcgi_active));
            
            if ((has_file || has_fcgi) && active_count < 256) {
                active_ids[active_count] = curr->stream_id;
                active_count++;
            }
            curr = curr->node_next;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);

    // --- 2. LOOP UTAMA PENGIRIMAN (FLUSH) ---
    for (int k = 0; k < active_count; k++) {
        uint32_t target_sid = active_ids[k];

        // --- A. PENANGANAN FASTCGI RESPONSE ---
        pthread_mutex_lock(&session->streams_lock);
        HTTP2Stream *st = http2_stream_find_unlocked(session, target_sid);
        if (st && st->state != HTTP2_STATE_CLOSED) {
            
            // Tahap 1: Kirim Header (Flag 0x04 = END_HEADERS)
            if (st->fcgi_h_ptr > 0 && !st->fcgi_header_sent) {
                st->fcgi_header_parsed = true;
                http2_response_send_complex_header(session, st, (char *)st->fcgi_header_buf, 0x04);
                st->fcgi_header_sent = true;
            }

            // Tahap 2: Pompa Body Data (Dukungan Buffer Dinamis / Streaming)
            if (st->fcgi_header_sent && (st->fcgi_g_ptr > st->fcgi_g_sent || !st->is_fcgi_active)) {
                size_t bytes_to_send = (st->fcgi_g_ptr > st->fcgi_g_sent) ? (st->fcgi_g_ptr - st->fcgi_g_sent) : 0;
                unsigned char *send_ptr = st->fcgi_gather_buf + st->fcgi_g_sent;

                uint32_t max_allowed = HTTP2_MAX_FRAME_SIZE;
                if ((int32_t)max_allowed > session->out_window_size) max_allowed = (uint32_t)session->out_window_size;
                if ((int32_t)max_allowed > st->out_window_size) max_allowed = (uint32_t)st->out_window_size;
                if (bytes_to_send > max_allowed) bytes_to_send = max_allowed;

                bool is_stream_finished = (!st->is_fcgi_active && (st->fcgi_g_sent + bytes_to_send >= st->fcgi_g_ptr));
                uint8_t flags = is_stream_finished ? 0x01 : 0x00; // 0x01 = END_STREAM

                if (bytes_to_send > 0 || is_stream_finished) {
                    http2_frame_send(session->fd, session->is_tls, 0x00, flags, target_sid, send_ptr, (uint32_t)bytes_to_send);

                    if (bytes_to_send > 0) {
                        session->out_window_size -= (int32_t)bytes_to_send;
                        st->out_window_size -= (int32_t)bytes_to_send;
                        st->fcgi_g_sent += bytes_to_send;
                    }

                    if (is_stream_finished) {
                        st->state = HTTP2_STATE_CLOSED;
                        st->is_fcgi_active = false;
                        if (st->fpm_fd >= 0) {
                            close(st->fpm_fd);
                            st->fpm_fd = -1;
                        }
                    }
                }
            }
        }
        pthread_mutex_unlock(&session->streams_lock);

        // --- B. PENANGANAN FILE STATIS ---
        int file_fd = -1;
        off_t offset = 0;
        off_t total_size = 0;
        int32_t conn_win = 0;
        int32_t stream_win = 0;
        bool valid_file = false;
 
        pthread_mutex_lock(&session->streams_lock);
        st = http2_stream_find_unlocked(session, target_sid);
        if (st && st->is_sending_file && st->file_fd >= 0 && st->state != HTTP2_STATE_CLOSED) {
            file_fd = st->file_fd;
            offset = st->file_offset;
            total_size = st->file_size;
            conn_win = session->out_window_size;
            stream_win = st->out_window_size;
            valid_file = true;
        }
        pthread_mutex_unlock(&session->streams_lock);
 
        if (!valid_file || file_fd < 0 || offset >= total_size) continue;
        if (conn_win <= 0 || stream_win <= 0) continue;
 
        off_t bytes_remaining = total_size - offset;
        uint32_t max_allowed_file = HTTP2_MAX_FRAME_SIZE; 
        if ((int32_t)max_allowed_file > conn_win) max_allowed_file = (uint32_t)conn_win;
        if ((int32_t)max_allowed_file > stream_win) max_allowed_file = (uint32_t)stream_win;
        if ((off_t)max_allowed_file > bytes_remaining) max_allowed_file = (uint32_t)bytes_remaining;
 
        if (max_allowed_file == 0) continue;
 
        unsigned char file_buf[HTTP2_MAX_FRAME_SIZE];
        ssize_t n_read = pread(file_fd, file_buf, max_allowed_file, offset);
 
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
 
        uint8_t file_flags = (offset + n_read >= total_size) ? 0x01 : 0x00;
        http2_frame_send(session->fd, session->is_tls, 0x00, file_flags, target_sid, file_buf, (uint32_t)n_read);
 
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

    // =========================================================================
    // --- 3. TAHAP PENYAPUAN & PENGHANCURAN STREAM YANG SUDAH CLOSED ---
    // =========================================================================
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        HTTP2Stream *prev = NULL;

        while (curr != NULL) {
            if (curr->state == HTTP2_STATE_CLOSED) {
                HTTP2Stream *to_free = curr;

                // Unlink dari hash table bucket
                if (prev == NULL) {
                    session->streams_hash[i] = curr->node_next;
                } else {
                    prev->node_next = curr->node_next;
                }
                curr = curr->node_next;

                // Kurangi counter aktif stream
                if (session->active_stream_count > 0) {
                    session->active_stream_count--;
                }

                // Bebaskan seluruh memori stream termasuk fcgi_gather_buf
                http2_stream_destroy(to_free);
            } else {
                prev = curr;
                curr = curr->node_next;
            }
        }
    }
    pthread_mutex_unlock(&session->streams_lock);
}

bool http2_response_has_active_streams(HTTP2Session *session) {
    if (!session) return false;
    bool has_active = false;
 
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            bool has_file = (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED);
            
            // bool has_fcgi = curr->is_fcgi_active;
            // Ini kasusnya sama dengan yang aku tulis di funsgi atas itu!
            // harus ditambahi curr->state != HTTP2_STATE_CLOSED
            bool has_fcgi = (curr->state != HTTP2_STATE_CLOSED && curr->is_fcgi_active);

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
