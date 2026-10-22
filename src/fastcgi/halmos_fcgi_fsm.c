#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_http2_core.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_poller.h"
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

// Helper internal pengiriman data ke klien (mendukung TLS / Plaintext)
static ssize_t worker_smart_send(int fd, const void *buf, size_t len, bool is_tls, SSL *ssl_conn) {
    if (is_tls && ssl_conn) {
        size_t total_sent = 0;
        const char *ptr = (const char*)buf;
        while (total_sent < len) {
            ssize_t n = ssl_send(fd, ptr + total_sent, len - total_sent);
            if (n > 0) {
                total_sent += n;
            } else {
                return -1;
            }
        }
        return total_sent;
    } else {
        size_t total_sent = 0;
        const char *ptr = (const char*)buf;
        while (total_sent < len) {
            ssize_t n = send(fd, ptr + total_sent, len - total_sent, MSG_NOSIGNAL);
            if (n > 0) {
                total_sent += n;
            } else if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                return -1;
            } else {
                return -1;
            }
        }
        return total_sent;
    }
}

// ==========================================
// 1. FSM STEP KHUSUS HTTP/1.1 (Logika Asli Langsung Kirim ke Klien)
// ==========================================
static bool halmos_fcgi_fsm_step_http1(HalmosFCGISession *session) {
    if (!session || session->fpm_fd == -1) return false;

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    if (n_head <= 0) {
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
            char *payload = malloc(clen);
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) break;
                    read_bytes += nr;
                }

                if (!session->header_sent) {
                    char *delim = strstr(payload, "\r\n\r\n");
                    if (delim) {
                        int h_only_len = (delim - payload) + 4;
                        int body_len = clen - h_only_len;

                        const char *default_resp = "HTTP/1.1 200 OK\r\nServer: Halmos\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
                        worker_smart_send(session->sock_client, default_resp, strlen(default_resp), session->is_tls, session->ssl_conn);

                        char chunk_header[32];
                        int ch_len = snprintf(chunk_header, sizeof(chunk_header), "%X\r\n", h_only_len);
                        worker_smart_send(session->sock_client, chunk_header, ch_len, session->is_tls, session->ssl_conn);
                        worker_smart_send(session->sock_client, payload, h_only_len, session->is_tls, session->ssl_conn);
                        worker_smart_send(session->sock_client, "\r\n", 2, session->is_tls, session->ssl_conn);

                        if (body_len > 0) {
                            ch_len = snprintf(chunk_header, sizeof(chunk_header), "%X\r\n", body_len);
                            worker_smart_send(session->sock_client, chunk_header, ch_len, session->is_tls, session->ssl_conn);
                            worker_smart_send(session->sock_client, payload + h_only_len, body_len, session->is_tls, session->ssl_conn);
                            worker_smart_send(session->sock_client, "\r\n", 2, session->is_tls, session->ssl_conn);
                        }

                        session->header_sent = true;
                    }
                } else {
                    char chunk_header[32];
                    int ch_len = snprintf(chunk_header, sizeof(chunk_header), "%X\r\n", clen);
                    worker_smart_send(session->sock_client, chunk_header, ch_len, session->is_tls, session->ssl_conn);
                    worker_smart_send(session->sock_client, payload, clen, session->is_tls, session->ssl_conn);
                    worker_smart_send(session->sock_client, "\r\n", 2, session->is_tls, session->ssl_conn);
                }

                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (session->header_sent) {
            worker_smart_send(session->sock_client, "0\r\n\r\n", 5, session->is_tls, session->ssl_conn);
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
        halmos_fcgi_poller_add(session->fpm_fd, session, EPOLLIN);
    }

    return true; 
}

// ==========================================
// 2. FSM STEP KHUSUS HTTP/2 (Kerangka / Placeholder Awal)
// ==========================================
static bool halmos_fcgi_fsm_step_http2(HalmosFCGISession *session) {
    if (!session || session->fpm_fd == -1) return false;

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    if (n_head <= 0) {
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
    
    // AMBIL LANGSUNG STREAM DARI SESSION H2 (Pastikan session->h2_session dan session->h2_stream sinkron)
    HTTP2Stream *stream = session->h2_stream;

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1); // Tambah 1 untuk null terminator
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) break;
                    read_bytes += nr;
                }
                payload[read_bytes] = '\0'; // Aman dicetak sebagai string

                // --- TAMBAHAN DEBUG MENTAH FPM ---
                fprintf(stderr, "[FCGI-RAW] Received %d bytes from FPM:\n%.*s\n--- END RAW ---\n", 
                        read_bytes, (int)read_bytes, payload);

                if (stream) {
                    int payload_offset = 0;

                    if (!stream->fcgi_header_parsed) {
                        size_t space_left = FCGI_HEADER_BUF_SIZE - stream->fcgi_h_ptr - 1;
                        size_t to_copy = (size_t)(read_bytes - payload_offset) < space_left ? (size_t)(read_bytes - payload_offset) : space_left;

                        if (to_copy > 0) {
                            memcpy(stream->fcgi_header_buf + stream->fcgi_h_ptr, payload + payload_offset, to_copy);
                            stream->fcgi_h_ptr += to_copy;
                            stream->fcgi_header_buf[stream->fcgi_h_ptr] = '\0';
                            payload_offset += to_copy;
                        }

                        char *sep = strstr((char *)stream->fcgi_header_buf, "\r\n\r\n");
                        if (!sep) {
                            sep = strstr((char *)stream->fcgi_header_buf, "\n\n"); // Fallback deteksi newline ganda biasa
                        }

                        if (sep) {
                            stream->fcgi_header_parsed = true;
                            
                            // Hitung posisi awal body yang sebenarnya
                            size_t header_len_actual = (size_t)(sep - stream->fcgi_header_buf) + (sep[0] == '\r' ? 4 : 2);
                            
                            // Jika ada sisa byte di dalam buffer header yang masuk wilayah body
                            if (stream->fcgi_h_ptr > header_len_actual) {
                                size_t spill_len = stream->fcgi_h_ptr - header_len_actual;
                                size_t body_space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;
                                
                                if (spill_len <= body_space_left) {
                                    memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, stream->fcgi_header_buf + header_len_actual, spill_len);
                                    stream->fcgi_g_ptr += spill_len;
                                }
                                // Koreksi ulang ukuran buffer header murni
                                stream->fcgi_h_ptr = header_len_actual;
                                stream->fcgi_header_buf[header_len_actual] = '\0';
                            }

                            // Jika ada sisa payload setelah pemisah yang belum masuk
                            if (payload_offset < read_bytes) {
                                int body_chunk = read_bytes - payload_offset;
                                size_t body_space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;

                                if ((size_t)body_chunk <= body_space_left) {
                                    memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, body_chunk);
                                    stream->fcgi_g_ptr += body_chunk;
                                }
                            }
                        }
                    } else {
                        int body_chunk = read_bytes - payload_offset;
                        size_t space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;

                        if (body_chunk > 0 && (size_t)body_chunk <= space_left) {
                            memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, body_chunk);
                            stream->fcgi_g_ptr += body_chunk;
                        }
                    }
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
            
            fprintf(stderr, "[FCGI-FSM] Stream %u Done | Header: %zu bytes | Body: %zu bytes\n", 
                    stream->stream_id, stream->fcgi_h_ptr, stream->fcgi_g_ptr);
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
        halmos_fcgi_poller_add(session->fpm_fd, session, EPOLLIN);
    }

    return true;
}

// ==========================================
// 3. ROUTER UTAMA FSM STEP (Pemanggil Dispatcher)
// ==========================================
bool halmos_fcgi_fsm_step(HalmosFCGISession *session) {
    if (!session) return false;
    
    if (session->is_http2) {
        return halmos_fcgi_fsm_step_http2(session);
    } else {
        return halmos_fcgi_fsm_step_http1(session);
    }
}