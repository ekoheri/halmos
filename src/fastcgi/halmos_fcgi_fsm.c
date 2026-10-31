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

static void handle_payload(bool *header_parsed, 
                           size_t *h_ptr, char *h_buf_target, 
                           size_t *g_ptr, unsigned char *g_buf_target, 
                           const char *payload, int read_bytes) {
    int payload_offset = 0;

    // 1. Jika header belum selesai di-parsing, isi dulu buffer header
    if (!(*header_parsed)) {
        size_t space_left = FCGI_HEADER_BUF_SIZE - (*h_ptr) - 1;
        size_t to_copy = (size_t)read_bytes < space_left ? (size_t)read_bytes : space_left;

        if (to_copy > 0) {
            memcpy(h_buf_target + (*h_ptr), payload, to_copy);
            (*h_ptr) += to_copy;
            h_buf_target[*h_ptr] = '\0';
            payload_offset += to_copy;
        }

        // Cari delimiter pemisah header dan body (\r\n\r\n atau \n\n)
        char *sep = strstr(h_buf_target, "\r\n\r\n");
        if (!sep) sep = strstr(h_buf_target, "\n\n");

        if (sep) {
            *header_parsed = true;
            size_t header_len = (size_t)(sep - h_buf_target) + (sep[0] == '\r' ? 4 : 2);
            
            // Jika ada sisa byte di h_buf yang sebenarnya sudah masuk wilayah body (spillover)
            if ((*h_ptr) > header_len) {
                size_t spill_len = (*h_ptr) - header_len;
                size_t body_space = GATHER_BUF_SIZE - (*g_ptr);
                if (spill_len <= body_space) {
                    memcpy(g_buf_target + (*g_ptr), h_buf_target + header_len, spill_len);
                    (*g_ptr) += spill_len;
                }
                *h_ptr = header_len;
                h_buf_target[header_len] = '\0';
            }
        }
    }

    // 2. Sisa payload (atau seluruh payload jika header sudah lama parsed) langsung masuk ke body gather buffer
    if (payload_offset < read_bytes) {
        int body_chunk = read_bytes - payload_offset;
        size_t space_left = GATHER_BUF_SIZE - (*g_ptr);

        if (body_chunk > 0 && (size_t)body_chunk <= space_left) {
            memcpy(g_buf_target + (*g_ptr), payload + payload_offset, body_chunk);
            (*g_ptr) += body_chunk;
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

                handle_payload(&session->fcgi_header_parsed,
                            &session->fcgi_h_ptr, (char *)session->fcgi_header_buf,
                            &session->fcgi_g_ptr, session->fcgi_gather_buf,
                            payload, read_bytes);
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
                    handle_payload(&stream->fcgi_header_parsed,
                                &stream->fcgi_h_ptr, stream->fcgi_header_buf,
                                &stream->fcgi_g_ptr, stream->fcgi_gather_buf,
                                payload, read_bytes);
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

