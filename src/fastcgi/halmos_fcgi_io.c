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
 * halmos_smart_send: Wrapper internal untuk memastikan data terkirim
 * baik lewat SSL atau socket biasa.
 */

static ssize_t halmos_smart_send(int fd, const void *buf, size_t len, bool is_tls) {
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

/**
 * halmos_fcgi_splice_response: Otak dari streaming response Backend.
 */
int halmos_fcgi_splice_response(int fpm_fd, int sock_client, RequestHeader *req) {
    unsigned char h_buf[8];
    int pipe_fds[2];
    bool is_tls = req->is_tls;
    bool use_splice = !is_tls; // Splice HANYA untuk non-TLS
    
    char body_temp[16384];
    char header_buffer[8192]; 
    int header_pos = 0;
    bool header_sent = false;
    bool is_redirect = false;
    int success = 0;

    if (use_splice && pipe(pipe_fds) < 0) {
        write_log_error("[IO] Splice failed, falling back to copy mode: %s", strerror(errno));
        use_splice = false;
    }

    // Loop membaca FastCGI Record dari Backend
    while (recv(fpm_fd, h_buf, 8, MSG_WAITALL) == 8) {
        HalmosFCGI_Header *h = (HalmosFCGI_Header *)h_buf;
        int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int plen = h->paddingLength;

        if (h->type == FCGI_STDOUT && clen > 0) {
            if (!header_sent) {
                // --- FASE 1: PARSING HEADER HTTP DARI BACKEND ---
                int space = sizeof(header_buffer) - header_pos - 1;
                int to_read = (clen < space) ? clen : space;
                recv(fpm_fd, header_buffer + header_pos, to_read, MSG_WAITALL);
                header_pos += to_read;
                header_buffer[header_pos] = '\0';

                char *delim = strstr(header_buffer, "\r\n\r\n");
                if (delim) {
                    // Deteksi Status Code
                    int status_code = 200;
                    char *s_ptr = strcasestr(header_buffer, "Status:");
                    if (s_ptr) status_code = atoi(s_ptr + 8);
                    else if (strcasestr(header_buffer, "Location:")) status_code = 302;
                    
                    is_redirect = (status_code >= 300 && status_code < 400);

                    // 1. Kirim Status Line Halmos
                    char res_start[512];
                    int s_len = snprintf(res_start, sizeof(res_start),
                        "HTTP/1.1 %d %s\r\n"
                        "Server: Halmos-Savage/2.1\r\n"
                        "%sConnection: %s\r\n",
                        status_code, get_status_text(status_code),
                        is_redirect ? "" : "Transfer-Encoding: chunked\r\n",
                        req->is_keep_alive ? "keep-alive" : "close");
                    
                    halmos_smart_send(sock_client, res_start, s_len, is_tls);

                    // 2. Kirim Header murni dari PHP (Content-Type, Set-Cookie, dll)
                    int h_only_len = (delim - header_buffer) + 4; 
                    halmos_smart_send(sock_client, header_buffer, h_only_len, is_tls);
                    header_sent = true;

                    // 3. Kirim Body yang 'ikut' di buffer header tadi
                    int body_in_buf = header_pos - h_only_len;
                    if (!is_redirect && body_in_buf > 0) {
                        char sz[16];
                        int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", body_in_buf);
                        halmos_smart_send(sock_client, sz, sz_l, is_tls);
                        halmos_smart_send(sock_client, header_buffer + h_only_len, body_in_buf, is_tls);
                        halmos_smart_send(sock_client, "\r\n", 2, is_tls);
                    }

                    // 4. Handle sisa clen di record pertama ini
                    int remain = clen - to_read;
                    if (remain > 0) {
                        if (!is_redirect) {
                            char sz[16];
                            int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", remain);
                            halmos_smart_send(sock_client, sz, sz_l, is_tls);
                        }
                        
                        while (remain > 0) {
                            int pull = (remain > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : remain;
                            recv(fpm_fd, body_temp, pull, MSG_WAITALL);
                            if (!is_redirect) halmos_smart_send(sock_client, body_temp, pull, is_tls);
                            remain -= pull;
                        }
                        if (!is_redirect) halmos_smart_send(sock_client, "\r\n", 2, is_tls);
                    }
                }
            } else {
                // --- FASE 2: STREAMING BODY (CHUNKED) ---
                if (!is_redirect) {
                    char sz[16];
                    int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", clen);
                    halmos_smart_send(sock_client, sz, sz_l, is_tls);
                }

                if (use_splice) {
                    // JALUR TOL KERNEL (NON-TLS)
                    splice(fpm_fd, NULL, pipe_fds[1], NULL, clen, SPLICE_F_MOVE);
                    splice(pipe_fds[0], NULL, sock_client, NULL, clen, SPLICE_F_MOVE);
                } else {
                    // JALUR USER-SPACE (TLS ATAU FALLBACK)
                    int to_pull = clen;
                    while (to_pull > 0) {
                        int pull = (to_pull > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : to_pull;
                        recv(fpm_fd, body_temp, pull, MSG_WAITALL);
                        if (!is_redirect) halmos_smart_send(sock_client, body_temp, pull, is_tls);
                        to_pull -= pull;
                    }
                }
                if (!is_redirect) halmos_smart_send(sock_client, "\r\n", 2, is_tls);
            }
        } 
        else if (h->type == FCGI_STDERR && clen > 0) {
            char *err = malloc(clen + 1);
            if (err) {
                recv(fpm_fd, err, clen, MSG_WAITALL);
                err[clen] = '\0';
                write_log_error("[PHP-ERR] %s", err);
                free(err);
            }
        }
        else if (h->type == FCGI_END_REQUEST) {
            // Akhiri Chunked Encoding
            if (!is_redirect) halmos_smart_send(sock_client, "0\r\n\r\n", 5, is_tls);
            success = 1;
            // Buang sisa data end-request
            char junk[32];
            recv(fpm_fd, junk, clen + plen, MSG_WAITALL);
            break;
        }

        // Handle Padding
        if (plen > 0 && h->type != FCGI_END_REQUEST) {
            char dummy[256];
            recv(fpm_fd, dummy, plen, MSG_WAITALL);
        }
    }

    if (use_splice) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }
    return (success) ? 0 : -1;
}