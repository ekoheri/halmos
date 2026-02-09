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

int handle_http1_session(int sock_client) {
    int keep_alive_status = 1;

    // --- OPTIMASI 1: Start Lean (8KB Default) ---
    // Balik ke cara lama: jangan booking RAM gede di depan.
    size_t current_buf_limit = (config.request_buffer_size > 0) ? config.request_buffer_size : 8192;
    char *buffer = (char *)malloc(current_buf_limit);
    if (!buffer) {
        close(sock_client);
        return -1;
    }

    while (keep_alive_status) {
        RequestHeader req_header;
        memset(&req_header, 0, sizeof(RequestHeader));
        
        // Cukup nol-kan byte pertama, jangan memset seluruh buffer (Save CPU!)
        buffer[0] = '\0';

        // --- 2. Terima Header ---
        ssize_t received = recv(sock_client, buffer, current_buf_limit - 1, 0);
        if (received <= 0) break; 
        buffer[received] = '\0';

        // --- 3. Parsing (Zero-Copy) ---
        if (!parse_http_request(buffer, (size_t)received, &req_header) || !req_header.is_valid) {
            send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
            free_request_header(&req_header);
            break; 
        }

        // --- 4. Dynamic Body Expansion (Lazy Allocation) ---
        bool body_error = false;
        if (req_header.content_length > 0) {
            size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
            
            if ((size_t)req_header.content_length > max_allowed) {
                send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413</h1>", false);
                body_error = true;
            } else {
                // Hitung total buffer yang dibutuhin (Header + Content-Length)
                size_t header_len = (char*)req_header.body_data - buffer;
                size_t total_needed_size = header_len + req_header.content_length;

                // Realloc buffer utama HANYA jika body lebih gede dari buffer 8KB awal
                if (total_needed_size > current_buf_limit) {
                    char *new_buf = (char *)realloc(buffer, total_needed_size + 1);
                    if (!new_buf) {
                        body_error = true;
                    } else {
                        // SYNC POINTER: Karena alamat buffer pindah, semua pointer di req_header harus di-update!
                        size_t body_offset = (char*)req_header.body_data - buffer;
                        buffer = new_buf;
                        req_header.body_data = buffer + body_offset;
                        current_buf_limit = total_needed_size + 1;
                    }
                }

                if (!body_error) {
                    // Tarik sisa body menggunakan logika lo yang solid
                    char *ptr = (char *)req_header.body_data + req_header.body_length;
                    size_t total_needed_recv = req_header.content_length - req_header.body_length;
                    int retry_count = 0;

                    while (total_needed_recv > 0 && retry_count < 100) {
                        ssize_t n = recv(sock_client, ptr, total_needed_recv, 0);
                        if (n > 0) {
                            ptr += n;
                            total_needed_recv -= n;
                            req_header.body_length += n;
                            retry_count = 0;
                        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            struct pollfd pfd = {.fd = sock_client, .events = POLLIN};
                            if (poll(&pfd, 1, 100) <= 0) retry_count++;
                            continue;
                        } else {
                            body_error = true;
                            break;
                        }
                    }
                    if (total_needed_recv > 0) body_error = true;
                    buffer[header_len + req_header.body_length] = '\0';
                }
            }
        }

        // --- 5. Eksekusi Multipart (Hanya jika body lengkap) ---
        /*if (!body_error && req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
            parse_multipart_body(&req_header);
        }*/

        // --- 6. Routing & Response ---
        if (!body_error) {
            // Get Client IP (Cara lama lo yang akurat)
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
                inet_ntop(AF_INET, &addr.sin_addr, req_header.client_ip, 45);
            }
            
            process_request_routing(sock_client, &req_header);
        }

        keep_alive_status = req_header.is_keep_alive;
        free_request_header(&req_header);

        if (!keep_alive_status || body_error) break;
    }

    // --- 7. Clean Exit (Shutdown & Drain Junk) ---
    if (buffer) free(buffer);
    shutdown(sock_client, SHUT_WR);
    char junk[1024];
    while(recv(sock_client, junk, sizeof(junk), MSG_DONTWAIT) > 0);
    close(sock_client);
    
    return 0;
}