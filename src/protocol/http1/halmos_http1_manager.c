#include "halmos_http1_manager.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_http1_parser.h"
#include "halmos_http1_response.h"
#include "halmos_multipart.h"
#include "halmos_http_utils.h"
#include "halmos_security.h"
#include "halmos_config.h"  // Di sini variabel 'config' sudah ada (extern)
#include "halmos_log.h"     // Di sini variabel 'global_queue' sudah ada (extern)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>    // Wajib buat struct timeval
#include <sys/socket.h>  // Wajib buat setsockopt

#include <pthread.h>

// Objek Antrean Global (Pusat Kendali)
TaskQueue global_queue;

Config config;

int handle_http1_session(int sock_client) {
    int keep_alive_status = 1;
    int buf_size = config.max_body_size + 8192;
    
    // 1. Cek malloc dhisik, ojo langsung memset!
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) {
        write_log("Error: Gagal alokasi buffer manager.");
        close(sock_client);
        return -1;
    }

    while (keep_alive_status) {
        RequestHeader req_header;
        memset(&req_header, 0, sizeof(RequestHeader));
        memset(buffer, 0, buf_size);

        // 2. Terima data awal
        ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
        if (received <= 0) break; 
        
        buffer[received] = '\0';

        // 3. Parsing (Zero-Copy)
        if (!parse_http_request(buffer, (size_t)received, &req_header) || !req_header.is_valid) {
            break; 
        }

        // 4. Tarik sisa Body (Proteksi data buntung)
        int body_error = 0;
        if (req_header.content_length > 0) {
            // Hitung berapa yang benar-benar kurang
            ssize_t actual_body_received = (char*)(buffer + received) - (char*)req_header.body_data;
            
            if (actual_body_received < req_header.content_length) {
                size_t total_needed = req_header.content_length - actual_body_received;
                
                // Cek apakah buffer muat
                if (received + total_needed >= (size_t)buf_size) {
                    send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413 Payload Too Large</h1>", false);
                    body_error = 1;
                } else {
                    char *ptr = buffer + received;
                    int retry_count = 0;
                    while (total_needed > 0 && retry_count < 10) { // Turunkan retry ke 10 biar gak spam
                        ssize_t n = recv(sock_client, ptr, total_needed, 0);
                        if (n > 0) {
                            ptr += n;
                            total_needed -= n;
                            received += n; // Update total received juga!
                            retry_count = 0;
                        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            struct pollfd pfd = {.fd = sock_client, .events = POLLIN};
                            if (poll(&pfd, 1, 1000) <= 0) retry_count++; // Tunggu 1 detik
                            continue;
                        } else {
                            body_error = 1;
                            break;
                        }
                    }
                    if (total_needed > 0) body_error = 1;
                    
                    // Pastikan NULL terminator di ujung total data
                    buffer[received] = '\0';
                    // Update final body_length
                    req_header.body_length = (size_t)(ptr - (char*)req_header.body_data);
                }
            }
        }

        // 5. Eksekusi nek ora ono error neng body
        if (!body_error) {
            if (req_header.uri != NULL && strlen(req_header.uri) > 0) {
                if (strstr(req_header.uri, "favicon.ico")) {
                    send_mem_response(sock_client, 404, "Not Found", "", false);
                } else {
                    process_request_routing(sock_client, &req_header);
                }
            }
        }

        keep_alive_status = req_header.is_keep_alive;
        free_request_header(&req_header);

        if (!keep_alive_status || body_error) break;
    }

    // Clean up kabeh sakdurunge metu
    if (buffer) free(buffer);
    shutdown(sock_client, SHUT_WR);
    close(sock_client);
    return 0;
}


