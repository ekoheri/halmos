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
        memset(buffer, 0, 1024); 

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
        if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
            size_t total_needed = req_header.content_length - req_header.body_length;
            
            if (received + total_needed >= (size_t)buf_size) {
                send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413</h1>", false);
                body_error = 1;
            } else {
                char *ptr = buffer + received;
                int retry_count = 0;
                while (total_needed > 0 && retry_count < 100) {
                    ssize_t n = recv(sock_client, ptr, total_needed, 0);
                    if (n > 0) {
                        ptr += n;
                        total_needed -= n;
                        req_header.body_length += n; // Update panjang body
                        retry_count = 0;
                    } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        struct pollfd pfd = {.fd = sock_client, .events = POLLIN};
                        if (poll(&pfd, 1, 100) <= 0) retry_count++;
                        continue;
                    } else {
                        body_error = 1; // Koneksi putus tengah dalan
                        break;
                    }
                }
                
                // Kunci NULL di ujung body
                // Setekah loop sisa body selesai:
                if (ptr < buffer + buf_size) {
                    *ptr = '\0'; // Kunci disini!
                } else {
                    // Ini untuk jaga-jaga kalo datane pas banget dgn ukuran buffer
                    buffer[buf_size - 1] = '\0'; 
                }

                // Update body_length jadi total real yang ketrima
                req_header.body_length = (size_t)(ptr - (char*)req_header.body_data);
                // Kalo loop seleai tapi data masih kurang, berarti data buntung (Client nakal/lemot)
                if (total_needed > 0) body_error = 1;
            }
        }

        // 5. Eksekusi nek ora ono error neng body
        if (!body_error) {
            if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
                parse_multipart_body(&req_header);
            }

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


