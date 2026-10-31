#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_http2_core.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_event_loop.h"
#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_sec_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// Helper untuk memastikan kapasitas gather buffer mencukupi secara dinamis
static bool fcgi_session_ensure_capacity(FCGI_Session *session, size_t needed_bytes) {
    if (!session) return false;

    size_t required_space = session->fcgi_g_ptr + needed_bytes;
    
    // Jika kapasitas saat ini masih mencukupi, langsung kembalikan true
    if (required_space <= session->fcgi_g_capacity) {
        return true;
    }

    // Tentukan kapasitas baru (kelipatan 2 dari kapasitas sebelumnya, minimal 64KB)
    size_t new_cap = session->fcgi_g_capacity ? session->fcgi_g_capacity * 2 : 65536;
    while (required_space > new_cap) {
        new_cap *= 2;
    }

    unsigned char *new_buf = realloc(session->fcgi_gather_buf, new_cap);
    if (!new_buf) {
        return false; // Gagal alokasi memori (Out of Memory)
    }

    session->fcgi_gather_buf = new_buf;
    session->fcgi_g_capacity = new_cap;
    return true;
}

static void handle_payload(FCGI_Session *session, const char *payload, int read_bytes) {
    if (!session || read_bytes <= 0) return;

    int payload_offset = 0;

    // 1. Jika header belum selesai di-parsing, isi dulu buffer header
    if (!session->fcgi_header_parsed) {
        size_t space_left = FCGI_HEADER_BUF_SIZE - session->fcgi_h_ptr - 1;
        size_t to_copy = (size_t)read_bytes < space_left ? (size_t)read_bytes : space_left;

        if (to_copy > 0) {
            memcpy(session->fcgi_header_buf + session->fcgi_h_ptr, payload, to_copy);
            session->fcgi_h_ptr += to_copy;
            session->fcgi_header_buf[session->fcgi_h_ptr] = '\0';
            payload_offset += (int)to_copy;
        }

        // Cari delimiter pemisah header dan body (\r\n\r\n atau \n\n)
        char *sep = strstr((char *)session->fcgi_header_buf, "\r\n\r\n");
        if (!sep) sep = strstr((char *)session->fcgi_header_buf, "\n\n");

        if (sep) {
            session->fcgi_header_parsed = true;
            size_t header_len = (size_t)(sep - (char *)session->fcgi_header_buf) + (sep[0] == '\r' ? 4 : 2);
            
            // Jika ada sisa byte di header_buf yang masuk wilayah body (spillover)
            if (session->fcgi_h_ptr > header_len) {
                size_t spill_len = session->fcgi_h_ptr - header_len;
                unsigned char *spill_ptr = session->fcgi_header_buf + header_len;

                // Pastikan gather_buf cukup menampung spillover secara dinamis
                if (fcgi_session_ensure_capacity(session, spill_len)) {
                    memcpy(session->fcgi_gather_buf + session->fcgi_g_ptr, spill_ptr, spill_len);
                    session->fcgi_g_ptr += spill_len;
                }
                session->fcgi_h_ptr = header_len;
                session->fcgi_header_buf[header_len] = '\0';
            }
        }
    }

    // 2. Sisa payload (atau seluruh payload jika header sudah lama parsed) langsung masuk ke body gather buffer
    if (payload_offset < read_bytes) {
        int body_chunk = read_bytes - payload_offset;
        if (body_chunk > 0) {
            // Pastikan gather_buf cukup menampung chunk body secara dinamis
            if (fcgi_session_ensure_capacity(session, (size_t)body_chunk)) {
                memcpy(session->fcgi_gather_buf + session->fcgi_g_ptr, payload + payload_offset, (size_t)body_chunk);
                session->fcgi_g_ptr += (size_t)body_chunk;
            } else {
                fprintf(stderr, "[FCGI_FSM_ERROR] Failed to ensure capacity for large payload body!\n");
            }
        }
    }
}

static bool http2_stream_ensure_capacity(HTTP2Stream *stream, size_t needed_bytes) {
    if (!stream) return false;
    size_t required_space = stream->fcgi_g_ptr + needed_bytes;
    
    if (required_space <= stream->fcgi_g_capacity) return true;

    size_t new_cap = stream->fcgi_g_capacity ? stream->fcgi_g_capacity * 2 : 65536;
    while (required_space > new_cap) new_cap *= 2;

    unsigned char *new_buf = realloc(stream->fcgi_gather_buf, new_cap);
    if (!new_buf) return false;

    stream->fcgi_gather_buf = new_buf;
    stream->fcgi_g_capacity = new_cap;
    return true;
}

static void handle_payload_http2(HTTP2Stream *stream, const char *payload, int read_bytes) {
    if (!stream || read_bytes <= 0) return;

    int payload_offset = 0;

    if (!stream->fcgi_header_parsed) {
        size_t space_left = FCGI_HEADER_BUF_SIZE - stream->fcgi_h_ptr - 1;
        size_t to_copy = (size_t)read_bytes < space_left ? (size_t)read_bytes : space_left;

        if (to_copy > 0) {
            memcpy(stream->fcgi_header_buf + stream->fcgi_h_ptr, payload, to_copy);
            stream->fcgi_h_ptr += to_copy;
            stream->fcgi_header_buf[stream->fcgi_h_ptr] = '\0';
            payload_offset += (int)to_copy;
        }

        char *sep = strstr((char *)stream->fcgi_header_buf, "\r\n\r\n");
        if (!sep) sep = strstr((char *)stream->fcgi_header_buf, "\n\n");

        if (sep) {
            stream->fcgi_header_parsed = true;
            size_t header_len = (size_t)(sep - (char *)stream->fcgi_header_buf) + (sep[0] == '\r' ? 4 : 2);
            
            if (stream->fcgi_h_ptr > header_len) {
                size_t spill_len = stream->fcgi_h_ptr - header_len;
                unsigned char *spill_ptr = (unsigned char *)stream->fcgi_header_buf + header_len;

                if (http2_stream_ensure_capacity(stream, spill_len)) {
                    memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, spill_ptr, spill_len);
                    stream->fcgi_g_ptr += spill_len;
                }
                stream->fcgi_h_ptr = header_len;
                stream->fcgi_header_buf[header_len] = '\0';
            }
        }
    }

    if (payload_offset < read_bytes) {
        int body_chunk = read_bytes - payload_offset;
        if (body_chunk > 0) {
            if (http2_stream_ensure_capacity(stream, (size_t)body_chunk)) {
                memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, (size_t)body_chunk);
                stream->fcgi_g_ptr += (size_t)body_chunk;
            }
        }
    }
}

// ==========================================
// 1. FSM STEP KHUSUS HTTP/1.1
// ==========================================
bool fcgi_fsm_step_http1(FCGI_Session *session) {
    if (!session) return false;

    pthread_mutex_lock(&session->lock);
    if (session->fpm_fd < 0 || session->fpm_fd == -99) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    pthread_mutex_unlock(&session->lock);

    fprintf(stderr, "[DEBUG FSM H1] === START STEP == | session=%p, fpm_fd=%d\n", (void*)session, session->fpm_fd);

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    
    if (n_head <= 0) {
        session->is_fcgi_active = false;
        if (session->fpm_fd != -1 && session->fpm_fd != -99) {
            fcgi_event_loop_del(session->fpm_fd);
        }
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    
    if (n_head < 8) {
        pthread_mutex_unlock(&session->lock);
        return true;
    }

    FCGI_Header *h = (FCGI_Header *)h_buf;
    int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
    int plen = h->paddingLength;

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1);
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) break;
                    read_bytes += nr;
                }
                payload[read_bytes] = '\0';

                handle_payload(session, payload, read_bytes);
                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (!session->fcgi_header_parsed && session->fcgi_h_ptr > 0) {
            session->fcgi_header_parsed = true;
        }
        session->is_fcgi_active = false;
        if (session->fpm_fd != -1 && session->fpm_fd != -99) {
            fcgi_event_loop_del(session->fpm_fd);
        }
        pthread_mutex_unlock(&session->lock);
        return false; 
    }

    if (plen > 0) {
        char junk[256];
        int pad_read = 0;
        while (pad_read < plen) {
            int chunk = (plen - pad_read > (int)sizeof(junk)) ? (int)sizeof(junk) : (plen - pad_read);
            ssize_t nr = recv(session->fpm_fd, junk, chunk, 0);
            if (nr <= 0) break;
            pad_read += nr;
        }
    }

    pthread_mutex_unlock(&session->lock);

    if (session->fpm_fd != -1 && session->fpm_fd != -99) {
        fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
    }

    return true; 
}

// ==========================================
// 2. FSM STEP KHUSUS HTTP/2
// ==========================================
bool fcgi_fsm_step_http2(FCGI_Session *session) {
    if (!session) return false;

    pthread_mutex_lock(&session->lock);
    if (session->fpm_fd < 0 || session->fpm_fd == -99) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    pthread_mutex_unlock(&session->lock);

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    if (n_head <= 0) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    
    if (n_head < 8) {
        pthread_mutex_unlock(&session->lock);
        if (session->fpm_fd != -1) {
            fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
        }
        return true;
    }

    FCGI_Header *h = (FCGI_Header *)h_buf;
    int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
    int plen = h->paddingLength;
    
    HTTP2Stream *stream = (HTTP2Stream *)session->h2_stream;

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1);
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) break;
                    read_bytes += nr;
                }
                payload[read_bytes] = '\0';

                if (stream) {                    
                    handle_payload_http2(stream, payload, read_bytes);
                }
                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (stream) {
            if (!stream->fcgi_header_parsed && stream->fcgi_h_ptr > 0) {
                stream->fcgi_header_parsed = true;
            }
            stream->is_fcgi_active = false;
        }
        pthread_mutex_unlock(&session->lock);
        return false; 
    }

    if (plen > 0) {
        char junk[256];
        int pad_read = 0;
        while (pad_read < plen) {
            int chunk = (plen - pad_read > (int)sizeof(junk)) ? (int)sizeof(junk) : (plen - pad_read);
            ssize_t nr = recv(session->fpm_fd, junk, chunk, 0);
            if (nr <= 0) break;
            pad_read += nr;
        }
    }

    pthread_mutex_unlock(&session->lock);

    if (session->fpm_fd != -1) {
        fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
    }

    return true;
}

