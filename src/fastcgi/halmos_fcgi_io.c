#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_global.h"
#include "halmos_security.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

/**
 * Fungsi ini adalah "Jalur Tol" data.
 * Menggunakan splice() untuk memindahkan data secara efisien.
 */

// Helper kirim agar tidak duplikasi code
static ssize_t halmos_send(int fd, const void *buf, size_t len, int flags) {
    if (config.tls_enabled) {
        SSL *ssl = get_ssl_for_fd(fd);
        return SSL_write(ssl, buf, (int)len);
        ssize_t n = SSL_write(ssl, buf, (int)len); // Sekarang 'n' sudah ada
        if (n <= 0) {
            //fprintf(stderr, "[DEBUG-SSL] SSL_write ERROR: %d pada FD %d\n", 
            //        SSL_get_error(ssl, n), fd);
            return n;
        }
    }
    return send(fd, buf, len, flags);
}

int halmos_fcgi_splice_response(int fpm_fd, int sock_client, RequestHeader *req) {
    unsigned char h_buf[8];
    int pipe_fds[2];
    bool use_splice = !config.tls_enabled; // MATIKAN SPLICE JIKA TLS AKTIF
    
    // DEKLARASI BUFFER
    char body_temp[16384];

    // Pipe digunakan sebagai buffer perantara di level kernel untuk splice()
    if (use_splice && pipe(pipe_fds) < 0) {
        write_log_error("[IO] Gagal membuat pipe: %s", strerror(errno));
        use_splice = false;
    }

    int header_sent = 0;
    char header_buffer[8192]; 
    int header_pos = 0;
    int success = 0;

    // --- TAMBAHKAN INI DI LUAR WHILE ---
    bool is_redirect = false; 

    // Loop membaca FastCGI Record
    while (recv(fpm_fd, h_buf, 8, MSG_WAITALL) == 8) {
        HalmosFCGI_Header *h = (HalmosFCGI_Header *)h_buf;
        int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int plen = h->paddingLength;

        if (h->type == FCGI_STDOUT && clen > 0) {
            if (!header_sent) {
                // FASE 1: Parsing Header HTTP dari Backend
                int space = sizeof(header_buffer) - header_pos - 1;
                int to_read = (clen < space) ? clen : space;
                
                recv(fpm_fd, header_buffer + header_pos, to_read, MSG_WAITALL);
                header_pos += to_read;
                header_buffer[header_pos] = '\0';

                char *delim = strstr(header_buffer, "\r\n\r\n");
                if (delim) {
                    //fprintf(stderr, "\n--- RAW HEADER DARI PHP ---\n%s\n---------------------------\n", header_buffer);
                    int status_code = 200;
                    char *s_ptr = strcasestr(header_buffer, "Status:");
                    if (s_ptr) status_code = atoi(s_ptr + 8);
                    else if (strcasestr(header_buffer, "Location:")) status_code = 302;

                    // --- PERBAIKAN START ---
                    is_redirect = (status_code >= 300 && status_code < 400);
                    
                    //fprintf(stderr, "[DEBUG-FCGI] Terdeteksi Status: %d\n", status_code);
                    // 1. Kirim Status Line Halmos
                    char response_start[512];
                    int start_len = snprintf(response_start, sizeof(response_start),
                        "HTTP/1.1 %d %s\r\n"
                        "Server: Halmos-Core/2.1\r\n"
                        "%s" // Slot dinamis untuk Chunked
                        "Connection: %s\r\n",
                        status_code, get_status_text(status_code), 
                        is_redirect ? "" : "Transfer-Encoding: chunked\r\n", // Redirect jangan pakai chunked
                        (req && req->is_keep_alive) ? "keep-alive" : "close");
                    
                    // JANGAN gunakan MSG_MORE jika TLS aktif (SSL_write tidak butuh flag itu)
                    halmos_send(sock_client, response_start, start_len, config.tls_enabled ? 0 : MSG_MORE);

                    // 2. Kirim Header murni dari PHP
                    int header_only_len = (delim - header_buffer) + 4; 
                    halmos_send(sock_client, header_buffer, header_only_len, MSG_NOSIGNAL);
                    header_sent = 1;

                    // 3. Kirim BODY hanya jika BUKAN redirect
                    int body_in_buffer = header_pos - header_only_len;
                    if (!is_redirect && body_in_buffer > 0) {
                        char sz_buf[16];
                        int sz_len = snprintf(sz_buf, sizeof(sz_buf), "%X\r\n", body_in_buffer);
                        halmos_send(sock_client, sz_buf, sz_len, MSG_NOSIGNAL);
                        halmos_send(sock_client, header_buffer + header_only_len, body_in_buffer, MSG_NOSIGNAL);
                        halmos_send(sock_client, "\r\n", 2, MSG_NOSIGNAL);
                    }

                    // 4. Jalur Tol: Splice/TLS Body sisa
                    int remain_in_chunk = clen - to_read; 
                    if (remain_in_chunk > 0) {
                        if (use_splice) {
                            splice(fpm_fd, NULL, pipe_fds[1], NULL, remain_in_chunk, SPLICE_F_MOVE | SPLICE_F_MORE);
                            splice(pipe_fds[0], NULL, sock_client, NULL, remain_in_chunk, SPLICE_F_MOVE | SPLICE_F_MORE);
                        } else {
                            // Jalur TLS
                            if (!is_redirect) { // Hanya kirim chunk header jika bukan redirect
                                char sz_buf[16];
                                int sz_len = snprintf(sz_buf, sizeof(sz_buf), "%X\r\n", remain_in_chunk);
                                halmos_send(sock_client, sz_buf, sz_len, MSG_NOSIGNAL);
                            }
                            
                            while (remain_in_chunk > 0) {
                                size_t pull = ((size_t)remain_in_chunk > sizeof(body_temp)) ? sizeof(body_temp) : (size_t)remain_in_chunk;
                                recv(fpm_fd, body_temp, pull, MSG_WAITALL);
                                if (!is_redirect) halmos_send(sock_client, body_temp, pull, MSG_NOSIGNAL);
                                remain_in_chunk -= pull;
                            }
                            if (!is_redirect) halmos_send(sock_client, "\r\n", 2, MSG_NOSIGNAL);
                        }
                    }
                }
            } else {
                // FASE 2: Full Zero-Copy (Header sudah lewat, tinggal alirkan body)
                if(use_splice){
                    splice(fpm_fd, NULL, pipe_fds[1], NULL, clen, SPLICE_F_MOVE | SPLICE_F_MORE);
                    splice(pipe_fds[0], NULL, sock_client, NULL, clen, SPLICE_F_MOVE | SPLICE_F_MORE);
                } else {
                    // JALUR TLS: Gunakan loop agar tidak overflow buffer temp
                    char sz_buf[16];
                    int sz_len = snprintf(sz_buf, sizeof(sz_buf), "%X\r\n", clen);
                    halmos_send(sock_client, sz_buf, sz_len, MSG_NOSIGNAL);

                    int total_to_pull = clen;
                    while (total_to_pull > 0) {
                        size_t pull = ((size_t)total_to_pull > sizeof(body_temp)) ? sizeof(body_temp) : (size_t)total_to_pull;
                        recv(fpm_fd, body_temp, pull, MSG_WAITALL);
                        halmos_send(sock_client, body_temp, pull, MSG_NOSIGNAL);
                        total_to_pull -= pull;
                    }
                    halmos_send(sock_client, "\r\n", 2, MSG_NOSIGNAL);
                }
            }
        }
        else if (h->type == FCGI_STDERR && clen > 0) {
            int safe_err_len = (clen > 65535) ? 65535 : clen;
            char *err = malloc(safe_err_len + 1);
            if (err) {
                recv(fpm_fd, err, safe_err_len, MSG_WAITALL);
                err[safe_err_len] = '\0';
                write_log_error("[BACKEND-ERR] %s", err);
                free(err);
                
                // Jika masih ada sisa pesan error yang tidak terbaca, buang
                int remain = clen - safe_err_len;
                while (remain > 0) {
                    char trash[1024];
                    int r = recv(fpm_fd, trash, (remain > 1024 ? 1024 : remain), MSG_WAITALL);
                    if (r <= 0) break;
                    remain -= r;
                }
            }
        }
        else if (h->type == FCGI_END_REQUEST) {
            //fprintf(stderr, "[DEBUG-FCGI] Mengirim tanda TAMAT (Zero Chunk) FD %d\n", sock_client);
            halmos_send(sock_client, "0\r\n\r\n", 5, MSG_NOSIGNAL); 
            success = 1;
            // Bersihkan sisa data/junk paket END_REQUEST
            char junk[256];
            int total_junk = clen + plen;
            while (total_junk > 0) {
                int r = recv(fpm_fd, junk, (total_junk > 256 ? 256 : total_junk), MSG_WAITALL);
                if (r <= 0) break;
                total_junk -= r;
            }
            break;
        }

        // Handle padding FastCGI
        if (plen > 0 && h->type != FCGI_END_REQUEST) {
            unsigned char dummy[256];
            recv(fpm_fd, dummy, plen, MSG_WAITALL);
        }
    }

    //close(pipe_fds[0]);
    //close(pipe_fds[1]);
    //return success ? 0 : -1;
    if (use_splice) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }
    return success ? 0 : -1;
}