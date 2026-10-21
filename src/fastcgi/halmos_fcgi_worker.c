#include "halmos_fcgi_worker.h"
#include "halmos_global.h"
#include "halmos_http2_core.h"
#include "halmos_http2_stream.h"
#include "halmos_http2_frame.h"
#include "halmos_http2_response.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_poller.h"
#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_sec_tls.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>

// Variabel global untuk Worker Pool
static FCGIWorkerPool fcgi_worker_pool;

// Helper untuk mengecek status pool dari modul lain (seperti queue)
bool halmos_fcgi_is_running(void) {
    return fcgi_worker_pool.running;
}

bool halmos_fcgi_worker_pool_init(void) {
    // 1. Ambil nilai secara adaptif dari variabel global
    int worker_count = g_fcgi_pool_size;

    // 2. Internal Safety Clamp / Sanity Check
    if (worker_count < 2) {
        worker_count = 2; // Batas minimal aman agar poller tetap punya napas
    }
    if (worker_count > g_worker_max) {
        worker_count = g_worker_max; // Jangan melebihi ceiling hardware yang terdeteksi
    }

    fcgi_worker_pool.worker_count = worker_count;
    fcgi_worker_pool.running = true;

    fcgi_worker_pool.threads = (pthread_t*)malloc(sizeof(pthread_t) * worker_count);
    if (!fcgi_worker_pool.threads) {
        fprintf(stderr, "[FCGI WORKER] Memory allocation failed for worker threads!\n");
        return false;
    }

    for (int i = 0; i < worker_count; i++) {
        if (pthread_create(&fcgi_worker_pool.threads[i], NULL, halmos_fcgi_worker_routine, NULL) != 0) {
            fcgi_worker_pool.running = false;
            // Cleanup thread yang sudah terlanjur dibuat
            for (int j = 0; j < i; j++) {
                pthread_cancel(fcgi_worker_pool.threads[j]);
            }
            free(fcgi_worker_pool.threads);
            return false;
        }
    }

    return true;
}

void halmos_fcgi_worker_pool_stop(void) {
    fcgi_worker_pool.running = false;

    // Bangunkan semua worker yang sedang tertahan di antrean queue
    halmos_fcgi_queue_broadcast();

    if (fcgi_worker_pool.threads) {
        for (int i = 0; i < fcgi_worker_pool.worker_count; i++) {
            pthread_join(fcgi_worker_pool.threads[i], NULL);
        }
        free(fcgi_worker_pool.threads);
        fcgi_worker_pool.threads = NULL;
    }
}

void* halmos_fcgi_worker_routine(void *arg) {
    (void)arg;

    while (fcgi_worker_pool.running) {
        // Ambil task dari antrean secara thread-safe (blocking via condition variable)
        FCGITask *task = halmos_fcgi_queue_pop();
        if (!task) continue; // Jika NULL karena shutdown, loop akan aman mendeteksi running = false

        HalmosFCGISession *session = task->session;
        if (session) {
            if (task->type == FCGI_TASK_PROCESS_READ) {
                // Eksekusi langkah FSM
                bool active = halmos_fcgi_fsm_step(session);
                if (!active) {
                    // Sesi selesai atau error, hapus dari poller dan hancurkan
                    halmos_fcgi_poller_del(session->fpm_fd);
                    halmos_fcgi_session_destroy(session);
                }
            } else if (task->type == FCGI_TASK_DISCONNECT) {
                // Koneksi backend terputus/error
                halmos_fcgi_poller_del(session->fpm_fd);
                halmos_fcgi_session_destroy(session);
            }
        }

        free(task);
    }

    return NULL;
}

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

bool halmos_fcgi_fsm_step(HalmosFCGISession *session) {
    if (!session || session->fpm_fd == -1) return false;

    fprintf(stderr, "[FSM_DEBUG] Attempting to lock session %p\n", (void*)session);
    pthread_mutex_lock(&session->lock);
    fprintf(stderr, "[FSM_DEBUG] Session %p locked successfully\n", (void*)session);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    if (n_head <= 0) {
        fprintf(stderr, "[FSM_DEBUG] recv header failed or EOF, n_head=%zd\n", n_head);
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

    // --- CACHE / RESOLVE HTTP/2 CONTEXT DI ATAS ---
    HTTP2Session *h2_sess = NULL;
    HTTP2Stream *h2_stream = NULL;
    if (session->is_http2) {
        h2_sess = (HTTP2Session *)(uintptr_t)session->http2_session_ptr;
        if (h2_sess) {
            h2_stream = http2_stream_find(h2_sess, session->http2_stream_id);
        }
        fprintf(stderr, "[H2-FSM_DEBUG] Step resolved: h2_sess=%p, h2_stream=%p (stream_id=%u, type=%d)\n", 
                (void*)h2_sess, (void*)h2_stream, session->http2_stream_id, h->type);
    }
    // ----------------------------------------------

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

                        if (session->is_http2) {
                            fprintf(stderr, "[H2-FSM_DEBUG] Header found from PHP-FPM! h_only_len=%d, body_len=%d\n", h_only_len, body_len);
                            
                            if (h2_stream) {
                                char *raw_headers = malloc((size_t)h_only_len + 1);
                                if (raw_headers) {
                                    memcpy(raw_headers, payload, (size_t)h_only_len);
                                    raw_headers[h_only_len] = '\0';

                                    fprintf(stderr, "[H2-FSM_DEBUG] Calling http2_response_send_complex_header...\n");
                                    // Kirim dengan flag 0x04 (END_HEADERS) agar curl tahu blok header selesai
                                    http2_response_send_complex_header(h2_sess, h2_stream, raw_headers, 0x04);
                                    free(raw_headers);
                                }

                                if (body_len > 0) {
                                    fprintf(stderr, "[H2-FSM_DEBUG] Sending initial body chunk (%d bytes)...\n", body_len);
                                    http2_response_send_data(h2_sess, h2_stream, payload + h_only_len, (size_t)body_len, false);
                                }
                            }
                        } else {
                            // Jalur HTTP/1.1
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
                        }

                        session->header_sent = true;
                    }
                } else {
                    // Streaming Body Lanjutan
                    if (session->is_http2) {
                        if (h2_stream) {
                            http2_response_send_data(h2_sess, h2_stream, payload, (size_t)clen, false);
                        }
                    } else {
                        char chunk_header[32];
                        int ch_len = snprintf(chunk_header, sizeof(chunk_header), "%X\r\n", clen);
                        worker_smart_send(session->sock_client, chunk_header, ch_len, session->is_tls, session->ssl_conn);
                        worker_smart_send(session->sock_client, payload, clen, session->is_tls, session->ssl_conn);
                        worker_smart_send(session->sock_client, "\r\n", 2, session->is_tls, session->ssl_conn);
                    }
                }

                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (session->header_sent) {
            if (session->is_http2) {
                if (h2_stream) {
                    // Jika stream masih ada, kirim data kosong dengan flag END_STREAM (0x01)
                    http2_response_send_data(h2_sess, h2_stream, NULL, 0, true);
                } else if (h2_sess) {
                    // Fallback: Kirim frame DATA kosong berflag END_STREAM (0x01) 
                    // langsung menggunakan fungsi pengiriman frame HTTP/2 yang ada di project Anda.
                    // (Sesuaikan nama fungsi pengiriman frame Anda, misal: http2_frame_send)
                    http2_frame_send(h2_sess->fd, h2_sess->is_tls, 0x00, 0x01, session->http2_stream_id, NULL, 0);
                }
            } else {
                worker_smart_send(session->sock_client, "0\r\n\r\n", 5, session->is_tls, session->ssl_conn);
            }
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