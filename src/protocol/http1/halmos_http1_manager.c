#include "halmos_http1_manager.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_http1_parser.h"
#include "halmos_http1_response.h"
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_security.h"
#include "halmos_config.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>

static ssize_t halmos_recv(int fd, void *buf, size_t len, int flags) {
    if (config.tls_enabled) {
        SSL *ssl = get_ssl_for_fd(fd);
        if (!ssl) return -1;
        return SSL_read(ssl, buf, (int)len);
    }
    return recv(fd, buf, len, flags);
}

int handle_http1_session(int sock_client) {
    char client_ip[INET_ADDRSTRLEN] = "Unknown";
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    int keep_alive_status = 1;

    size_t current_buf_limit = (config.request_buffer_size > 0) ? config.request_buffer_size : 8192;
    char *buffer = (char *)malloc(current_buf_limit);
    if (!buffer) {
        write_log_error("[MEM] Failed to allocate initial HTTP buffer for FD %d", sock_client);
        close(sock_client);
        return -1;
    }

    while (keep_alive_status) {
        RequestHeader req_header;
        memset(&req_header, 0, sizeof(RequestHeader));
        
        buffer[0] = '\0';

        // --- 2. PERBAIKAN TERIMA HEADER (LOOPING + DEBUG) ---
        ssize_t total_received = 0;
        int timeout_retry = 0;

        while (total_received < (ssize_t)current_buf_limit - 1) {
            ssize_t n = halmos_recv(sock_client, buffer + total_received, current_buf_limit - total_received - 1, 0);
            
            if (n > 0) {
                total_received += n;
                buffer[total_received] = '\0';
                timeout_retry = 0; // Reset kalau ada progress
                if (strstr(buffer, "\r\n\r\n")) break; // HEADER LENGKAP!
            } 
            else {
                // Cek apakah ini cuma masalah Non-Blocking
                if (config.tls_enabled) {
                    SSL *ssl = get_ssl_for_fd(sock_client);
                    int ssl_err = SSL_get_error(ssl, (int)n);
                    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                        usleep(1000); // Tunggu 1ms
                        if (++timeout_retry < 500) continue; // Coba lagi sampai 0.5 detik
                    }
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(1000);
                    if (++timeout_retry < 500) continue;
                }
                
                // Kalau beneran 0 atau error fatal
                if (total_received == 0) goto exit_session;
                break;
            }
        }

        // --- DEBUG PRINT UNTUK BOSS ---
        //fprintf(stderr, "\n[DEBUG-RAW-HEADER] FD: %d | Total: %zd bytes\n%s\n", sock_client, total_received, buffer);

        // --- 3. Parsing (Zero-Copy) ---
        if (!parse_http_request(buffer, (size_t)total_received, &req_header) || !req_header.is_valid) {
            write_log_error("[HTTP] Bad Request from %s: Invalid protocol/header", client_ip);
            send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
            free_request_header(&req_header);
            break; 
        }

        // TAMBAHKAN INI BUAT CEK:
        //fprintf(stderr, "[DEBUG-BODY-CHECK] Content-Length: %ld | Body Length Already Read: %zu\n", 
        //(long)req_header.content_length, req_header.body_length);

        // --- 4. Dynamic Body Expansion (Tetap Sama) ---
        bool body_error = false;
        if (req_header.content_length > 0) {
            size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
            
            if ((size_t)req_header.content_length > max_allowed) {
                write_log_error("[HTTP] Payload too large from %s: %ld bytes", client_ip, (long)req_header.content_length);
                send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413</h1>", false);
                body_error = true;
            } else {
                size_t header_len = (char*)req_header.body_data - buffer;
                size_t total_needed_size = header_len + req_header.content_length;

                if (total_needed_size > current_buf_limit) {
                    char *old_buf = buffer; 
                    char *new_buf = (char *)realloc(buffer, total_needed_size + 1);
                    
                    if (!new_buf) {
                        write_log_error("[MEM] Failed to expand buffer");
                        body_error = true;
                    } else {
                        buffer = new_buf;
                        current_buf_limit = total_needed_size + 1;
                        ptrdiff_t diff = new_buf - old_buf;
                        
                        // 1. Geser semua pointer utama
                        if (req_header.uri)          req_header.uri += diff;
                        if (req_header.directory)    req_header.directory += diff;
                        if (req_header.query_string) req_header.query_string += diff;
                        if (req_header.host)         req_header.host += diff;
                        if (req_header.content_type) req_header.content_type += diff;
                        if (req_header.cookie_data)  req_header.cookie_data += diff;
                        if (req_header.body_data)    req_header.body_data = (void*)((char*)req_header.body_data + diff);

                        // 2. KHUSUS PATH_INFO: Jika dia tidak NULL, geser. 
                        // Jika log masih ngaco, paksa NULL dulu buat ngetes!
                        if (req_header.path_info) {
                            req_header.path_info += diff;
                        } else {
                            req_header.path_info = NULL; 
                        }
                                                
                        // FIX: Hapus baris 'ptr = ...' di sini karena belum dideklarasikan
                    }
                }

                if (!body_error) {
                    // POSISI START: Awal data body yang belum terbaca
                    char *ptr = (char *)req_header.body_data + req_header.body_length;
                    size_t total_needed_recv = req_header.content_length - req_header.body_length;
                    int body_retry = 0;

                    //fprintf(stderr, "[DEBUG-RECV-START] Menarik sisa: %zu bytes\n", total_needed_recv);

                    while (total_needed_recv > 0) {
                        ssize_t n = halmos_recv(sock_client, ptr, total_needed_recv, 0);
                        
                        if (n > 0) {
                            ptr += n;
                            total_needed_recv -= n;
                            req_header.body_length += n;
                            body_retry = 0; 
                        } else if (n < 0) {
                            int err_code = 0;
                            bool retry_it = false;

                            if (config.tls_enabled) {
                                SSL *ssl = get_ssl_for_fd(sock_client);
                                err_code = SSL_get_error(ssl, (int)n);
                                if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) retry_it = true;
                            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                retry_it = true;
                            }

                            if (retry_it) {
                                struct pollfd pfd = {.fd = sock_client, .events = POLLIN};
                                // TUNGGU SAMPAI DATA READY (100ms)
                                if (poll(&pfd, 1, 100) <= 0) {
                                    body_retry++;
                                }
                                if (body_retry < 500) continue; // Jangan menyerah dulu
                            }
                            
                            write_log_error("[RECV] Gagal narik body: %s", config.tls_enabled ? "SSL Error" : strerror(errno));
                            body_error = true;
                            break;
                        } else {
                            // n == 0 (Koneksi diputus peer)
                            write_log_error("[RECV] Koneksi putus saat upload");
                            body_error = true;
                            break;
                        }
                    }
                    
                    //if (!body_error) {
                    //    fprintf(stderr, "[DEBUG-RECV-SUCCESS] Berhasil narik %zu bytes body\n", req_header.body_length);
                    //}
                }
            }
        }

        // --- 5. Routing & Response ---
        if (!body_error) {
            process_request_routing(sock_client, &req_header);
        }

        keep_alive_status = req_header.is_keep_alive;
        free_request_header(&req_header);

        if (!keep_alive_status || body_error) break;
    }

exit_session:
    if (buffer) free(buffer);
    return keep_alive_status;
}

