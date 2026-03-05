#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_global.h"
#include "halmos_sec_tls.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <poll.h>

/**
 * fcgi_smart_send: Wrapper internal untuk memastikan data terkirim
 * baik lewat SSL atau socket biasa.
 */

static ssize_t fcgi_smart_send(int fd, const void *buf, size_t len, bool is_tls);
/**
 * fcgi_splice_response: Otak dari streaming response Backend.
 */

/**
 * fcgi_io_splice_response: Versi Ultimate (Anti-Hang & Anti-Poison)
 * Fix: Menambahkan timeout read agar worker tidak hang selamanya jika backend stuck.
 * Fix: Memastikan record dibaca sampai END_REQUEST untuk mencegah pool corruption.
 */
int fcgi_io_splice_response(int fpm_fd, int sock_client, RequestHeader *req) {
    unsigned char h_buf[8];
    int pipe_fds[2];
    bool is_tls = req->is_tls;
    bool use_splice = !is_tls;
    
    char body_temp[16384];
    char header_buffer[8192]; 
    int header_pos = 0;
    bool header_sent = false;
    bool is_redirect = false;
    int final_status = -1; // Default gagal (Poisoned state)

    // 1. SET TIMEOUT: Mencegah Worker Thread Hang Selamanya
    struct timeval tv;
    tv.tv_sec = 30; // Timeout 30 detik (Standar upstream)
    tv.tv_usec = 0;
    if (setsockopt(fpm_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        write_log_error("[FCGI] Warning: Could not set SO_RCVTIMEO: %s", strerror(errno));
    }

    if (use_splice && pipe(pipe_fds) < 0) {
        use_splice = false;
    }

    /* --- LOOP UTAMA: FASTCGI RECORD PARSING --- */
    while (1) {
        // Baca Header (MSG_WAITALL akan patuh pada SO_RCVTIMEO)
        ssize_t n_head = recv(fpm_fd, h_buf, 8, MSG_WAITALL);
        if (n_head != 8) {
            if (n_head < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                write_log_error("[FCGI] Timeout: Backend unresponsive for 30s at URI: %s", req->uri);
            } else {
                write_log_error("[FCGI] Connection lost/Header malformed.");
            }
            break; 
        }

        HalmosFCGI_Header *h = (HalmosFCGI_Header *)h_buf;
        int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int plen = h->paddingLength;

        if (h->type == FCGI_STDOUT) {
            if (clen > 0) {
                if (!header_sent) {
                    /* --- FASE 1: PARSING HEADER HTTP --- */
                    int space = sizeof(header_buffer) - header_pos - 1;
                    int to_read = (clen < space) ? clen : space;
                    
                    if (recv(fpm_fd, header_buffer + header_pos, to_read, MSG_WAITALL) != to_read) break;
                    header_pos += to_read;
                    header_buffer[header_pos] = '\0';

                    char *delim = strstr(header_buffer, "\r\n\r\n");
                    if (delim) {
                        int status_code = 200;
                        char *s_ptr = strcasestr(header_buffer, "Status:");
                        if (s_ptr) status_code = atoi(s_ptr + 8);
                        else if (strcasestr(header_buffer, "Location:")) status_code = 302;
                        is_redirect = (status_code >= 300 && status_code < 400);

                        char res_start[512];
                        int s_len = snprintf(res_start, sizeof(res_start),
                            "HTTP/1.1 %d %s\r\nServer: Halmos-Savage/2.1\r\n%sConnection: %s\r\n",
                            status_code, get_status_text(status_code),
                            is_redirect ? "" : "Transfer-Encoding: chunked\r\n",
                            req->is_keep_alive ? "keep-alive" : "close");
                        
                        if (fcgi_smart_send(sock_client, res_start, s_len, is_tls) < 0) break;
                        int h_only_len = (delim - header_buffer) + 4; 
                        if (fcgi_smart_send(sock_client, header_buffer, h_only_len, is_tls) < 0) break;
                        header_sent = true;

                        int body_in_buf = header_pos - h_only_len;
                        if (!is_redirect && body_in_buf > 0) {
                            char sz[16];
                            int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", body_in_buf);
                            fcgi_smart_send(sock_client, sz, sz_l, is_tls);
                            fcgi_smart_send(sock_client, header_buffer + h_only_len, body_in_buf, is_tls);
                            fcgi_smart_send(sock_client, "\r\n", 2, is_tls);
                        }

                        // Kuras sisa clen di record pertama
                        int remain = clen - to_read;
                        while (remain > 0) {
                            int pull = (remain > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : remain;
                            if (recv(fpm_fd, body_temp, pull, MSG_WAITALL) != pull) goto cleanup_error;
                            remain -= pull;
                        }
                    }
                } else {
                    /* --- FASE 2: STREAMING BODY (CHUNKED) --- */
                    if (!is_redirect) {
                        char sz[16];
                        int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", clen);
                        if (fcgi_smart_send(sock_client, sz, sz_l, is_tls) < 0) break;
                    }

                    if (use_splice) {
                        int to_move = clen;
                        while (to_move > 0) {
                            // 1. Pindahkan dari Backend ke Pipe (In)
                            ssize_t n_in = splice(fpm_fd, NULL, pipe_fds[1], NULL, to_move, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                            
                            if (n_in < 0) {
                                if (errno == EAGAIN || errno == EINTR) continue;
                                goto cleanup_error;
                            } else if (n_in == 0) goto cleanup_error; // Backend closed

                            // 2. Pindahkan dari Pipe ke Client (Out)
                            // Kita harus menguras apa yang baru saja masuk ke pipe
                            int pipe_level = (int)n_in;
                            while (pipe_level > 0) {
                                ssize_t n_out = splice(pipe_fds[0], NULL, sock_client, NULL, pipe_level, SPLICE_F_MOVE);
                                if (n_out <= 0) {
                                    if (n_out < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                                    goto cleanup_error; // Client closed/error
                                }
                                pipe_level -= (int)n_out;
                            }
                            
                            to_move -= (int)n_in;
                        }
                    } else {
                        int to_pull = clen;
                        while (to_pull > 0) {
                            int pull = (to_pull > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : to_pull;
                            if (recv(fpm_fd, body_temp, pull, MSG_WAITALL) != pull) goto cleanup_error;
                            if (!is_redirect) {
                                if (fcgi_smart_send(sock_client, body_temp, pull, is_tls) < 0) goto cleanup_error;
                            }
                            to_pull -= pull;
                        }
                    }
                    if (!is_redirect) fcgi_smart_send(sock_client, "\r\n", 2, is_tls);
                }
            }
        } 
        else if (h->type == FCGI_STDERR && clen > 0) {
            char *err_msg = malloc(clen + 1);
            if (err_msg) {
                //recv(fpm_fd, err_msg, clen, MSG_WAITALL);
                if (recv(fpm_fd, err_msg, clen, MSG_WAITALL) != clen)
                    goto cleanup_error;
                err_msg[clen] = '\0';
                write_log_error("[PHP-STDERR] %s", err_msg);
                free(err_msg);
            }
        }
        else if (h->type == FCGI_END_REQUEST) {
            unsigned char end_payload[8]; 
            if (recv(fpm_fd, end_payload, 8, MSG_WAITALL) == 8) {
                if (!is_redirect && header_sent) {
                    fcgi_smart_send(sock_client, "0\r\n\r\n", 5, is_tls);
                }
                final_status = 0; // KONDISI SUKSES MUTLAK
            }
            break; 
        }

        // Kuras Padding
        if (plen > 0) {
            char junk[256];
            if (recv(fpm_fd, junk, plen, MSG_WAITALL) != plen) break;
        }
    }

cleanup_error:
    if (use_splice) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }

    if (final_status != 0) {
        /* STATE INCONSISTENT: Socket beracun, buang dari pool! */
        write_log_error("[FCGI] Protocol Desync or Timeout. Closing backend socket.");
        close(fpm_fd); 
        return -2; 
    }

    return 0;
}

ssize_t fcgi_smart_send(int fd, const void *buf, size_t len, bool is_tls) {
    if (is_tls) {
        // Panggil fungsi pusat yang sudah pinter handle WANT_WRITE (code 3)
        // Kita loop di sini biar semua chunk datanya beneran keluar
        size_t total_sent = 0;
        while (total_sent < len) {
            ssize_t n = ssl_send(fd, (const char*)buf + total_sent, len - total_sent);
            if (n > 0) {
                total_sent += n;
            } else if (n == 0) {
                // Pakai wait_for_write yang kita buat di manager tadi
                // Kalau fungsi wait_for_write juga static, terpaksa bikin poll lokal di sini
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                poll(&pfd, 1, 10); 
            } else {
                return -1; // Fatal error
            }
        }
        return total_sent;
    }
    // Jalur Plaintext (Non-TLS)
    return send(fd, buf, len, MSG_NOSIGNAL);
}
