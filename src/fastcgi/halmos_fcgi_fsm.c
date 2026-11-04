#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_http2_core.h"
#include "halmos_http2_response.h"
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
#include <poll.h>

static ssize_t http1_session_write(FCGI_Session *session, const void *buf, size_t len) {
    if (!session || session->sock_client < 0) return -2;

    if (session->is_tls) {
        if (!session->ssl_conn) return -2;
        int written = SSL_write(session->ssl_conn, buf, (int)len);
        if (written <= 0) {
            int err = SSL_get_error(session->ssl_conn, written);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                errno = EAGAIN;
                return -1;
            }
            return -2;
        }
        return written;
    } else {
        ssize_t written = send(session->sock_client, buf, len, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -1;
            }
            return -2;
        }
        return written;
    }
}

static bool http1_send_chunk_safe(FCGI_Session *session, const unsigned char *data, size_t len) {
    if (len == 0) return true;

    char header_hex[32];
    int hex_len = snprintf(header_hex, sizeof(header_hex), "%zx\r\n", len);

    size_t total_sent = 0;
    while (total_sent < (size_t)hex_len) {
        ssize_t n = http1_session_write(session, header_hex + total_sent, (size_t)hex_len - total_sent);
        if (n < 0) {
            if (errno == EAGAIN) return false;
            return false;
        }
        total_sent += n;
    }

    // Gunakan ulang total_sent (JANGAN deklarasikan ulang dengan size_t di depan!)
    total_sent = 0;
    while (total_sent < len) {
        ssize_t n = http1_session_write(session, data + total_sent, len - total_sent);
        if (n > 0) {
            total_sent += (size_t)n;
        } else if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = session->sock_client, .events = POLLOUT };
                int pr = poll(&pfd, 1, 5000);
                if (pr > 0 && (pfd.revents & POLLOUT)) {
                    continue; 
                }
            }
            return false; 
        }
    }

    const char *crlf = "\r\n";
    total_sent = 0; // Gunakan ulang variabel yang sama
    while (total_sent < 2) {
        ssize_t n = http1_session_write(session, crlf + total_sent, 2 - total_sent);
        if (n < 0) {
            if (errno == EAGAIN) return false;
            return false;
        }
        total_sent += n;
    }

    return true;
}

static bool http1_send_terminal_chunk_safe(FCGI_Session *session) {
    const char *term = "0\r\n\r\n";
    size_t total_sent = 0;
    while (total_sent < 5) {
        ssize_t n = http1_session_write(session, term + total_sent, 5 - total_sent);
        if (n < 0) {
            if (errno == EAGAIN) return false;
            return false;
        }
        total_sent += n;
    }
    return true;
}

// Helper HTTP1 : untuk menghandle data (payload) yang diterima dari FPM menggunakan Ring Buffer statis
static void handle_payload_http1(FCGI_Session *session, const char *payload, int read_bytes);

// Helper HTTP2 : untuk menghandle data (payload) HTTP/2
static void handle_payload_http2(HTTP2Stream *stream, const char *payload, int read_bytes);

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

    pthread_mutex_lock(&session->lock);

    // --- 1. PENGAMBILAN HEADER AMAN (ANTI PECAHAN / PARTIAL READ) ---
    unsigned char h_buf[8];
    size_t header_read = 0;
    while (header_read < 8) {
        ssize_t n_head = recv(session->fpm_fd, h_buf + header_read, 8 - header_read, 0);
        if (n_head > 0) {
            header_read += n_head;
        } else if (n_head == 0) {
            session->is_fcgi_active = false;
            if (session->fpm_fd != -1 && session->fpm_fd != -99) {
                fcgi_event_loop_del(session->fpm_fd);
            }
            pthread_mutex_unlock(&session->lock);
            return false; 
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100); // Tunggu sebentar agar 8 byte header utuh terpenuhi
                continue;
            }
            session->is_fcgi_active = false;
            if (session->fpm_fd != -1 && session->fpm_fd != -99) {
                fcgi_event_loop_del(session->fpm_fd);
            }
            pthread_mutex_unlock(&session->lock);
            return false;
        }
    }
    // -------------------------------------------------------------

    FCGI_Header *h = (FCGI_Header *)h_buf;
    int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
    int plen = h->paddingLength;

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1);
            if (!payload) {
                write_log_error_code(ERR_FCGI_PAYLOAD_MEM, clen + 1);
            } else {
                int read_bytes = 0;
                // --- 2. PEMBACAAN PAYLOAD TANPA BATAS PAKSA (MENCEGAH LARGE DATA TERPOTONG) ---
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr > 0) {
                        read_bytes += nr;
                    } else if (nr == 0) {
                        break;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // Jangan di-break dengan retry_count! Biarkan terus menunggu sampai data besar tuntas.
                            usleep(500); 
                            continue;
                        } else {
                            break;
                        }
                    }
                }
                // --------------------------------------------------------------------------
                payload[read_bytes] = '\0';

                // Masukkan payload ke handler / ring buffer
                handle_payload_http1(session, payload, read_bytes);
                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (!session->fcgi_header_parsed && session->fcgi_h_ptr > 0) {
            session->fcgi_header_parsed = true;
        }
        session->is_fcgi_active = false;

        // --- KIRIM TERMINAL CHUNK HANYA JIKA KONEKSI MASIH VALID ---
        if (session->sock_client >= 0 && (!session->is_tls || session->ssl_conn != NULL)) {
            http1_send_terminal_chunk_safe(session);
        }

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
            if (!payload) {
                // [LOG TAMBAHAN] Kehabisan RAM saat mengalokasikan payload FPM
                write_log_error_code(ERR_FCGI_PAYLOAD_MEM, clen + 1);
            } else {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr > 0) {
                        read_bytes += nr;
                    } else if (nr == 0) {
                        break;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            usleep(500); 
                            continue;    
                        } else {
                            break;
                        }
                    }
                }
                payload[read_bytes] = '\0';

                if (stream) {                    
                    handle_payload_http2(stream, payload, read_bytes);
                    if (session->h2_session) {
                        http2_response_flush_active_streams(session->h2_session);
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

// ================================================================================
// HELPER (PRIVATE FUNCTION)
// ================================================================================

// Helper HTTP1 : Menulis payload langsung ke Ring Buffer statis session->rx_buffer
// Helper HTTP1 : Menulis payload langsung ke Ring Buffer statis session->rx_buffer
void handle_payload_http1(FCGI_Session *session, const char *payload, int read_bytes) {
    if (!session || read_bytes <= 0) return;

    int payload_offset = 0;

    // 1. Jika header PHP belum selesai di-parsing
    if (!session->fcgi_header_parsed) {
        size_t space_left = sizeof(session->fcgi_header_buf) - session->fcgi_h_ptr - 1;
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
            
            // --- PARSING STATUS CODE YANG AMAN ---
            int status_code = 200;
            char status_text[32] = "OK";

            char *line = (char *)session->fcgi_header_buf;
            while (line < sep) {
                char *next_line = strstr(line, "\r\n");
                int delim_len = 2;
                if (!next_line || next_line > sep) {
                    next_line = strstr(line, "\n");
                    delim_len = 1;
                }
                if (!next_line) break;

                // Simpan karakter asli sebelum disuntik \0 (Mencegah kerusakan delimiter \r\n)
                char orig_c = *next_line;
                *next_line = '\0';

                if (strncasecmp(line, "Status:", 7) == 0) {
                    char *val = line + 7;
                    while (*val == ' ' || *val == '\t') val++;
                    status_code = atoi(val);
                    if (status_code == 404) snprintf(status_text, sizeof(status_text), "Not Found");
                    else if (status_code == 500) snprintf(status_text, sizeof(status_text), "Internal Server Error");
                    else if (status_code == 403) snprintf(status_text, sizeof(status_text), "Forbidden");
                    else if (status_code == 302) snprintf(status_text, sizeof(status_text), "Found");
                }

                // Kembalikan karakter asli dengan benar
                *next_line = orig_c;
                line = next_line + delim_len;
            }

            // --- SUSUN HEADER ---
            char combined_resp[8192];
            int comb_len = snprintf(combined_resp, sizeof(combined_resp),
                                    "HTTP/1.1 %d %s\r\n"
                                    "Server: Halmos-Savage/2.1\r\n"
                                    "Connection: keep-alive\r\n"
                                    "Transfer-Encoding: chunked\r\n",
                                    status_code, status_text);

            if (header_len < sizeof(combined_resp) - comb_len) {
                memcpy(combined_resp + comb_len, session->fcgi_header_buf, header_len);
                comb_len += header_len;
            }

            // Kirim header gabungan ke browser
            http1_session_write(session, combined_resp, (size_t)comb_len);

            // Jika ada sisa byte (spillover) -> Gunakan http1_send_chunk_safe agar format hex chunk terjaga
            if (session->fcgi_h_ptr > header_len) {
                size_t spill_len = session->fcgi_h_ptr - header_len;
                unsigned char *spill_ptr = (unsigned char *)(session->fcgi_header_buf + header_len);

                if (spill_len > 0) {
                    http1_send_chunk_safe(session, spill_ptr, spill_len);
                }
            }

            session->fcgi_h_ptr = header_len;
            session->fcgi_header_buf[header_len] = '\0';
        }
    }

    // 2. Sisa payload berikutnya (Body besar / Large Data)
    if (payload_offset < read_bytes) {
        int body_chunk = read_bytes - payload_offset;
        if (body_chunk > 0) {
            if (session->fcgi_header_parsed) {
                http1_send_chunk_safe(session, (unsigned char *)(payload + payload_offset), (size_t)body_chunk);
            } else {
                fcgi_ring_write(&session->rx_buffer, payload + payload_offset, (size_t)body_chunk);
            }
        }
    }
}

// Helper HTTP2 : Handle payload HTTP/2
void handle_payload_http2(HTTP2Stream *stream, const char *payload, int read_bytes) {
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

                // Jika stream HTTP/2 masih menggunakan buffer dinamisnya sendiri, biarkan atau sesuaikan.
                // Fokus utama migrasi pool adalah pada FCGI_Session HTTP/1.
                if (stream->fcgi_g_ptr + spill_len <= stream->fcgi_g_capacity) {
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
            if (stream->fcgi_g_ptr + (size_t)body_chunk <= stream->fcgi_g_capacity) {
                memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, (size_t)body_chunk);
                stream->fcgi_g_ptr += (size_t)body_chunk;
            }
        }
    }
}