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

// Pastikan urutan include benar
#include "config.h"  // Di sini variabel 'config' sudah ada (extern)
#include "log.h"     // Di sini variabel 'global_queue' sudah ada (extern)
#include "queue.h"     // Di sini variabel 'global_queue' sudah ada (extern)
#include "http1_parser.h"
#include "http1_response.h"
#include "multipart.h"
#include "rate_limit.h"

// Objek Antrean Global (Pusat Kendali)
TaskQueue global_queue;

/***********************************************************************
 * handle_http1_session()
 * ANALOGI BESAR FUNGSI INI :
 * Fungsi ini adalah seperti PETUGAS FRONT OFFICE di sebuah kantor
 * yang menerima tamu dari pintu masuk sampai diarahkan ke layanan
 * yang sesuai.
 *
 * Tugas utamanya:
 * 1. Menerima surat dari tamu (recv)
 * 2. Membaca dan memeriksa formulir (parsing HTTP)
 * 3. Mengecek apakah berkas lengkap atau rusak
 * 4. Jika ada lampiran besar → ditunggu sampai selesai
 * 5. Jika formulir multipart → kirim ke bagian pembongkar berkas
 * 6. Menyerahkan pekerjaan ke pelayan sesuai metode (GET/POST)
 * 7. Mencatat aktivitas di buku tamu (log)
 *
 * Jika ada masalah di salah satu tahap,
 * petugas langsung menolak dengan surat balasan resmi.
 ***********************************************************************/

int handle_http1_session(int sock_client) {
    int keep_alive_status = 1;

    /**************************************************************
     * A. LOOPING SESSION (KEEP-ALIVE)
     * Selama browser minta 'keep-alive', loket tetap terbuka.
     **************************************************************/
    while (keep_alive_status) {
        
        // 1. Alokasi buffer untuk Header
        int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
        char *buffer = (char *)malloc(buf_size);
        if (!buffer) break; 

        // 2. Menerima data (Recv akan timeout sesuai tv_sec)
        ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
        if (received <= 0) { 
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                write_log("[DEBUG] Connection timeout for socket %d", sock_client);
            }
            free(buffer); 
            break; 
        }
        buffer[received] = '\0';

        // 3. Parsing HTTP Header
        RequestHeader req_header; 
        memset(&req_header, 0, sizeof(RequestHeader));
        
        if (!parse_http_request(buffer, (size_t)received, &req_header) || !req_header.is_valid) {
            send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
            free(buffer);
            free_request_header(&req_header); 
            break; 
        }

        /**************************************************************
         * 4. Membaca sisa Body (Jika ada Content-Length)
         **************************************************************/
        bool body_error = false;
        if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
            size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
            
            if ((size_t)req_header.content_length > max_allowed) {
                send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413 Payload Too Large</h1>", false);
                body_error = true;
            } else {
                void *new_body = realloc(req_header.body_data, req_header.content_length + 1);
                if (!new_body) { 
                    write_log("Out of memory during body realloc");
                    body_error = true;
                } else {
                    req_header.body_data = new_body;
                    char *ptr = (char *)req_header.body_data + req_header.body_length;
                    size_t total_needed = req_header.content_length - req_header.body_length;

                    int retry_count = 0;
                    const int MAX_RETRY = 100; // Cukup 10 detik (100 * 100ms)

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
                                struct pollfd pfd = {.fd = sock_client, .events = POLLIN};
                                if (poll(&pfd, 1, 100) <= 0) retry_count++; 
                                continue;
                            }
                            break;
                        }
                    }

                    if (retry_count >= MAX_RETRY) {
                        write_log("Timeout: Client failed to send full body");
                        send_mem_response(sock_client, 408, "Request Timeout", "<h1>408 Request Timeout</h1>", false);
                        body_error = true;
                    }
                }
            }
        }

        // Jika terjadi error saat tarik body, kita stop session ini
        if (body_error) {
            free(buffer);
            free_request_header(&req_header);
            break;
        }

        // Tambahkan null terminator pada body
        if (req_header.body_data) {
            ((char*)req_header.body_data)[req_header.body_length] = '\0';
            if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
                parse_multipart_body(&req_header);
            }
        }

        /**************************************************************
         * 5. Identitas & Keamanan (Rate Limit)
         **************************************************************/
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
            inet_ntop(AF_INET, &addr.sin_addr, req_header.client_ip, 45);
        }

        if (config.rate_limit_enabled) {
            int rps_limit = config.max_requests_per_sec > 0 ? config.max_requests_per_sec : 20;
            if (!is_request_allowed(req_header.client_ip, rps_limit)) {
                send_mem_response(sock_client, 429, "Too Many Requests", "<h1>429 Santai Cuk!</h1>", false);
                free(buffer);
                free_request_header(&req_header);
                break; 
            }
        }

        /**************************************************************
         * 6. EKSEKUSI METHOD (Static/Dynamic)
         **************************************************************/
        handle_method(sock_client, req_header);

        // Update status keep-alive untuk putaran loop berikutnya
        keep_alive_status = req_header.is_keep_alive;

        write_log("Thread Monitoring | Request: %s | Method: %s | Connection: %s",
              req_header.uri, req_header.method, keep_alive_status ? "Keep-Alive" : "Close");

        /**************************************************************
         * 7. CLEANUP PER-REQUEST
         **************************************************************/
        free(buffer);
        free_request_header(&req_header);

        // Jika client minta tutup, ya kita break
        if (!keep_alive_status) break;
    }

    /**************************************************************
     * D. PINTU KELUAR TUNGGAL
     * Socket ditutup sekali di sini setelah loop selesai.
     **************************************************************/
    close(sock_client);
    return 0;
}