#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

// Pastikan urutan include benar
#include "../../../include/core/config.h"  // Di sini variabel 'config' sudah ada (extern)
#include "../../../include/core/log.h"     // Di sini variabel 'global_queue' sudah ada (extern)
#include "../../../include/core/queue.h"     // Di sini variabel 'global_queue' sudah ada (extern)
#include "../../../include/protocols/http1/http1_parser.h"
#include "../../../include/protocols/http1/http1_response.h"
#include "../../../include/handlers/multipart.h"

// Objek Antrean Global (Pusat Kendali)
TaskQueue global_queue;

int handle_http1_session(int sock_client) {
    int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) return 0; // Kembalikan 0 jika gagal alokasi

    // 1. Baca data pertama
    ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
    if (received <= 0) { 
        free(buffer); 
        close(sock_client); 
        return 0; // Gagal baca, tutup koneksi
    }
    buffer[received] = '\0';

    // 2. Eksekusi Parsing (Memanggil modul http_parser.c)
    // Kita gunakan parse_http_request yang di dalamnya sudah mencakup 
    // logika parse_request_line kompleks.

    RequestHeader req_header; 
    memset(&req_header, 0, sizeof(RequestHeader));
    
    bool success = parse_http_request(buffer, (size_t)received, &req_header);

    // 3. Cek validitas (Sesuai dengan logika asli Anda)
    if (!success || !req_header.is_valid) {
        // Memanggil fungsi response (nanti ada di http_response.c)
        send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
        
        // Pembersihan sesuai kebutuhan
        free_request_header(&req_header); 
        close(sock_client);
        return 0; 
    }

    // 3. Baca sisa body jika belum lengkap
    if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
        
        size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
        if ((size_t)req_header.content_length > max_allowed) {
            send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413 Payload Too Large</h1>", false);
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0;
        }

        void *new_body = realloc(req_header.body_data, req_header.content_length + 1);
        if (!new_body) { 
            write_log("Out of memory during body realloc");
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0; 
        }
        req_header.body_data = new_body;

        char *ptr = (char *)req_header.body_data + req_header.body_length;
        size_t total_needed = req_header.content_length - req_header.body_length;

        int retry_count = 0;
        const int MAX_RETRY = 5000;

        while (total_needed > 0 && retry_count < MAX_RETRY) {
            ssize_t n = recv(sock_client, ptr, total_needed, 0);
            if (n > 0) {
                ptr += n;
                total_needed -= n;
                req_header.body_length += n;
                retry_count = 0;
            } else if (n == 0) {
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd;
                    pfd.fd = sock_client;
                    pfd.events = POLLIN;
                    // Tunggu maksimal 100ms, tapi bangun seketika data datang
                    int poll_res = poll(&pfd, 1, 100); 
                    if (poll_res <= 0) retry_count++; 
                    continue;
                }
                break;
            }
        }

        if (retry_count >= MAX_RETRY) {
            write_log("Timeout: Client failed to send full body");
            send_mem_response(sock_client, 408, "Request Timeout", "<h1>408 Request Timeout</h1>", false);
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0;
        }

        ((char*)req_header.body_data)[req_header.body_length] = '\0';

        // khusus menangani post data multipart
        if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
            parse_multipart_body(&req_header);
        }
    }

    free(buffer); 

    // Ambil status sebelum struct dibebaskan
    int keep_alive_status = req_header.is_keep_alive;

    // 1. TAMBAHKAN DISINI (Logika ambil IP)
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "0.0.0.0";

    // Fungsi getpeername mengambil info dari socket yang sedang aktif
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    // 5. Proses Method
    handle_method(sock_client, req_header);

    // Tambahkan Log Monitoring
    write_log("Thread Monitoring | Active: %d/%d | Request: %s | Method: %s | Connection: %s",
          global_queue.active_workers, 
          global_queue.total_workers,
          req_header.uri,
          req_header.method,
          keep_alive_status ? "Keep-Alive" : "Close");

    free_request_header(&req_header);
    
    // Logika Hybrid: Jika bukan keep-alive, tutup socket di sini
    /*if (!keep_alive_status) {
        close(sock_client);
    }*/

    return keep_alive_status;
}