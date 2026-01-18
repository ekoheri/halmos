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
#include "../../../include/security/rate_limit.h"

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
     /**************************************************************
    * 1. Alokasi buffer
     * ANALOGI :
     * Petugas menyiapkan MAP KOSONG untuk menampung surat dari tamu.
     * Ukuran map mengikuti aturan kantor (config.request_buffer_size).
     * Kalau map tidak bisa disiapkan → tamu langsung ditolak.
     **************************************************************/
    int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) return 0; 

    /**************************************************************
     * 2. Menerima data pertama
     * ANALOGI :
     * Petugas membuka pintu dan menerima halaman pertama surat.
     * Kalau tamu langsung pergi atau surat kosong,
     * maka loket ditutup kembali.
     **************************************************************/
    ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
    if (received <= 0) { 
        free(buffer); 
        close(sock_client); 
        return 0; 
    }
    buffer[received] = '\0';

    /**************************************************************
     * 3. Parsing HTTP
     * ANALOGI :
     * Surat diberikan ke BAGIAN ADMIN untuk dibaca:
     * - siapa pengirim?
     * - mau layanan apa?
     * - ada lampiran berapa halaman?
     *
     * Ini dilakukan oleh modul parse_http_request.
     **************************************************************/
    RequestHeader req_header; 
    memset(&req_header, 0, sizeof(RequestHeader));
    
    bool success = parse_http_request(buffer, (size_t)received, &req_header);

    
    /**************************************************************
     * 4. Validasi permintaan
     * ANALOGI :
     * Jika formulir tidak sesuai format:
     * → petugas mengembalikan surat “400 Bad Request”
     *    seperti loket yang bilang:
     *    “Maaf formulir Anda salah isi.”
     **************************************************************/
    if (!success || !req_header.is_valid) {
        // Memanggil fungsi response (nanti ada di http_response.c)
        send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
        
        // Pembersihan sesuai kebutuhan
        free_request_header(&req_header); 
        close(sock_client);
        return 0; 
    }

     /**************************************************************
     * 5. Membaca sisa body
     * ANALOGI :
     * Kalau tamu membawa berkas tebal:
     * petugas tidak bisa terima sekali,
     * harus dicicil halaman demi halaman.
     *
     * Juga ada aturan:
     * - tidak boleh lebih besar dari batas kantor
     * - kalau kelamaan kirim → dianggap kabur (timeout)
     **************************************************************/
    if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
        // tidak boleh lebih besar dari batas yang ditetapkan yaitu 50MB
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
        // kalau kelamaan kirim → dianggap kabur (timeout)
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
        // Kalau tamu (browser )membawa berkas tebal,
        // misal gambar besar, PDF, dll.
        // Petugas tidak bisa terima sekali,
        // harus dicicil halaman demi halaman (chunk).
        if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
            parse_multipart_body(&req_header);
        }
    }

    free(buffer); 

    // Ambil status sebelum struct dibebaskan
    int keep_alive_status = req_header.is_keep_alive;

    // Logika ambil IP
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "0.0.0.0";

    // Fungsi getpeername mengambil info dari socket yang sedang aktif
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    // Salin ke struct agar bisa dipakai di modul lain (seperti PHP/Python)
    strncpy(req_header.client_ip, client_ip, 45);

    if (config.rate_limit_enabled) {
        int rps_limit = config.max_requests_per_sec > 0 ? config.max_requests_per_sec : 20;
        if (!is_request_allowed(req_header.client_ip, rps_limit)) {
            write_log("[SECURITY] Rate limit exceeded for IP: %s\n", req_header.client_ip);
            
            char *msg = "<h1>429 Too Many Requests</h1><p>Santai Cuk, jangan ngebut-ngebut!</p>";
            char response[512];
            sprintf(response, 
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s", 
                strlen(msg), msg);
                
            send(sock_client, response, strlen(response), 0);
            free_request_header(&req_header);
            return 0; // Tendang!
        }
    }
    
    // Proses Method
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
    // Tapi karena browser mayoritas keep-alive, maka ini di-remark
    /*if (!keep_alive_status) {
        close(sock_client);
    }*/

    return keep_alive_status;
}