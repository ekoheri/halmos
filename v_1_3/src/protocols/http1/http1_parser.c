#define _GNU_SOURCE // Penting untuk memmem()

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <regex.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

//Tambahan untuk library zerro-copy
#include <sys/sendfile.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>  // Wajib untuk fungsi stat() dan makro S_ISREG
#include <sys/types.h> // Mendukung definisi tipe data sistem

//// Fungsi untuk membersihkan path dan mencegah traversal
#include <limits.h>

#include <sched.h>   // Header untuk sched_yield()

#include "../include/core/fs_handler.h"
#include "../include/core/config.h"
#include "../include/core/log.h"
#include "../include/core/queue.h"

#include "../include/handlers/fastcgi.h"
#include "../include/handlers/multipart.h"

#include "../include/protocols/common/http_utils.h"
#include "../include/protocols/common/http_common.h"
#include "../include/protocols/http1/http1_parser.h"
#include "../include/protocols/http1/http1_response.h"


#define BUFFER_SIZE 1024

extern Config config;

extern TaskQueue global_queue;

/********************************************************************
 * parse_request_line()
 * ANALOGI :
 * Petugas loket yang membaca BARIS PERTAMA surat pesanan.
 *
 * Tamu datang membawa tulisan:
 *    "GET /produk?id=10 HTTP/1.1"
 *
 * Tugas petugas ini:
 * - Memisahkan jenis layanan  → GET / POST (seperti jenis menu)
 * - Memisahkan alamat tujuan  → /produk
 * - Membaca catatan kecil     → ?id=10 (query string)
 * - Mengetahui gaya bahasa    → HTTP/1.1
 *
 * Kalau formatnya rusak → petugas langsung bilang:
 * “Maaf formulir tidak terbaca.”
 ********************************************************************/
static void parse_request_line(char *line, RequestHeader *req) {
    char *m = strtok(line, " ");
    char *u = strtok(NULL, " ");
    char *v = strtok(NULL, " ");

    if (m && u) {
        strncpy(req->method, m, sizeof(req->method) - 1);
        if (v) strncpy(req->http_version, v, sizeof(req->http_version) - 1);

        // 1. Pisahkan Query String jika ada
        char *q = strchr(u, '?');
        if (q) {
            req->query_string = strdup(q + 1);
            url_decode(req->query_string); // Gunakan fungsi dari utils.c
            *q = '\0';
        } else {
            req->query_string = strdup("");
        }

        // 2. Simpan URI dan Decode
        req->uri = strdup((u[0] == '/' && u[1] == '\0') ? "index.html" : u);
        url_decode(req->uri); 
        
        req->is_valid = true;
    }
}

/********************************************************************
 * parse_http_request()
 * ANALOGI :
 * Bagian Tata Usaha yang MEMBUKA AMPLOP surat secara lengkap.
 *
 * Langkah kerjanya seperti:
 * 1. Mencari lipatan surat (\r\n\r\n atau Enter 2 kali) → batas kop surat & isi
 * 2. Memanggil petugas pembaca judul (parse_request_line)
 * 3. Membaca keterangan tambahan:
 *      - Content-Length  → tebal isi surat
 *      - Content-Type    → jenis lampiran
 * 4. Menyalin isi surat ke map kerja (body)
 * 5. Kalau isinya paket multipart → kirim ke petugas bongkar paket
 *
 * Hasilnya:
 * → formulir digital yang rapi siap diproses pelayan.
 ********************************************************************/
bool parse_http_request(const char *raw_data, size_t total_received, RequestHeader *req) {
    // 1. Cari batas Header (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    if (!header_end) return false;

    size_t header_len = header_end - raw_data;
    char *header_tmp = strndup(raw_data, header_len);

    // 2. Parse Baris Pertama
    char *saveptr;
    char *line = strtok_r(header_tmp, "\r\n", &saveptr);
    if (line) {
        parse_request_line(line, req);
    }

    // 3. Loop Parsing Header Lainnya (Content-Length, Type, Connection)
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            req->content_length = atol(line + 15);
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            req->content_type = strdup(line + 13);
            trim_whitespace(req->content_type); // Gunakan fungsi dari utils.c
        } else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (strcasestr(line, "keep-alive")) req->is_keep_alive = true;
            else if (strcasestr(line, "close")) req->is_keep_alive = false;
        }
    }
    free(header_tmp);

    // 4. Salin Body (Logika Binary Safe Anda)
    if (req->content_length > 0) {
        char *body_start = (char *)header_end + 4;
        size_t bytes_in_buffer = total_received - (body_start - raw_data);
        
        req->body_data = malloc(req->content_length + 1);
        if (req->body_data) {
            size_t to_copy = (bytes_in_buffer > (size_t)req->content_length) 
                             ? (size_t)req->content_length : bytes_in_buffer;
            
            memcpy(req->body_data, body_start, to_copy);
            req->body_length = to_copy;
            
            // Safety null terminator untuk data teks
            ((char*)req->body_data)[to_copy] = '\0';
        }
    }

    // 5. Jika Multipart, panggil modul multipart
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        parse_multipart_body(req);
    }

    return req->is_valid;
}

/********************************************************************
 * free_request_header()
 * ANALOGI :
 * Petugas kebersihan meja arsip.
 *
 * Setelah pesanan selesai:
 * - fotokopi dibuang,
 * - map dikosongkan,
 * - meja disiapkan untuk tamu berikutnya.
 *
 * Tanpa petugas ini:
 * → kantor akan penuh sampah memori.
 ********************************************************************/
void free_request_header(RequestHeader *req) {
    if (req->uri) free(req->uri);
    if (req->query_string) free(req->query_string);
    if (req->content_type) free(req->content_type);
    if (req->body_data) free(req->body_data);
    
    // Bersihkan bagian multipart jika ada
    if (req->parts) {
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].name) free(req->parts[i].name);
            if (req->parts[i].filename) free(req->parts[i].filename);
            if (req->parts[i].data) free(req->parts[i].data);
            if (req->parts[i].content_type) free(req->parts[i].content_type);
        }
        free(req->parts);
    }
}

/********************************************************************
 * handle_get_request()
 * ANALOGI :
 * Pelayan yang melayani tamu tipe GET : “hanya ingin melihat/mengambil”.
 *
 * Alur kerjanya seperti:
 * 1. Satpam cek alamat aman (tidak boleh keluar area)
 * 2. Tentukan tujuan:
 *    - Kalau PHP  → kirim ke dapur PHP via FastCGI
 *    - Kalau Rust → kirim ke dapur Rust via FastCGI
 *    - Kalau file biasa → ambil dari gudang
 *
 * Saat ambil file:
 * → pakai sendfile seperti conveyor,
 *   barang dikirim tanpa dipegang tangan pelayan.
 ********************************************************************/
void handle_get_request(int sock_client, RequestHeader *req) {
    char *safe_file_path = NULL;
    // 1. Cek apakah ini request untuk Rust (Bypass pengecekan fisik)
    if (strstr(req->uri, config.rust_ext)) {
        // 1.a.Kita buat path virtual secara manual tanpa realpath()
        char virtual_path[PATH_MAX];
        snprintf(virtual_path, sizeof(virtual_path), "%s%s", config.document_root, req->uri);
        
        // Duplikasi string agar konsisten dengan return sanitize_path yang menggunakan malloc
        safe_file_path = strdup(virtual_path); 
    } else {
        // 1.b. Jika bukan Rust, gunakan sanitasi ketat (realpath)
        safe_file_path = sanitize_path(config.document_root, req->uri);
    }

    if (safe_file_path == NULL) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    // 2. Kalau PHP  → kirim ke dapur PHP via FastCGI
    if (strstr(req->uri, ".php")) {
        // 2.1. Panggil fungsi FastCGI yang dibuat di handlers/fastcgi.c
        FastCGI_Response res = fastcgi_request(
            config.php_server,
            config.php_port,
            "",                     // directory
            req->uri,               // script_name
            req->method, 
            req->query_string ? req->query_string : "",
            "",                     // path_info
            "",                     // post_data
            0,                      // post_data_len
            ""                      // content_type
        );
        // 2.2 Hasil dari PHP kirim balik ke browser
        if (res.body != NULL) {
            char header[1024];
            int h_len = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n"
                "Server: Halmos-Core\r\n"
                "Connection: keep-alive\r\n\r\n",
                strlen(res.body));
            
            send(sock_client, header, h_len, 0);
            send(sock_client, res.body, strlen(res.body), 0);

            // Bebaskan memori yang dialokasikan
            if (res.header) free(res.header);
            if (res.body) free(res.body);
        } else {
            // kalau body kosong, maka kirimkan keterangan 504 gateway timeout
            send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>504 Gateway Timeout</h1>", req->is_keep_alive);
        }
        
        free(safe_file_path);
        return; 
    }

    // 3. Kalau Rust → kirim ke dapur Rust via FastCGI
    if (strstr(req->uri, config.rust_ext)) {
        // 3.1. Bersihkan path
        char clean_path[PATH_MAX];
        memset(clean_path, 0, sizeof(clean_path));
        int j = 0;
        for (int i = 0; req->uri[i] != '\0' && i < PATH_MAX - 1; i++) {
            if (req->uri[i] == '/' && req->uri[i+1] == '/') continue;
            clean_path[j++] = req->uri[i];
        }
        clean_path[j] = '\0';

        // 3.2. Panggil Rust via FastCGI
        FastCGI_Response res_rust = fastcgi_request(
            config.rust_server, 
            config.rust_port, 
            "", 
            clean_path, 
            req->method, 
            req->query_string ? req->query_string : "", 
            "", 
            "",  // post_data
            0,   // post_data_len (TAMBAHKAN INI)
            ""   // content_type (TAMBAHKAN INI)
        );

        // 3.3 Hasil dari Rust kirim balik ke browser
        if (res_rust.body != NULL) {
            char header[1024];
            size_t body_len = strlen(res_rust.body);
            
            int h_len = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n"
                "Server: Halmos-Core\r\n"
                "Connection: %s\r\n\r\n", 
                body_len, 
                req->is_keep_alive ? "keep-alive" : "close");
            
            // Kirim Header (kop surat) ke browser
            send(sock_client, header, h_len, 0);
            
            // Kirim Body hasil eksekusi Rust ke browser
            send(sock_client, res_rust.body, body_len, 0);

            // Bersihkan memori
            if (res_rust.header) free(res_rust.header);
            if (res_rust.body) free(res_rust.body);
        } else {
            // kalau body kosong, maka kirimkan keterangan 504 gateway timeout
            send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>504 Gateway Timeout</h1>", req->is_keep_alive);
        }
        free(safe_file_path);
        return;
    }
    // 4. Logika File Statis : Kalau file biasa → ambil dari gudang
    struct stat st;
    if (stat(safe_file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        free(safe_file_path);
        return;
    }

    // Ambil MIME Type
    const char *mime = get_mime_type(req->uri);
    
    // Siapkan Header
    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: Halmos-Core\r\n"
        "Connection: keep-alive\r\n\r\n",
        mime, st.st_size);

    send(sock_client, header, h_len, 0);

    // Kirim File dengan Zero-Copy (Looping untuk Non-Blocking)
    int fd = open(safe_file_path, O_RDONLY);
    if (fd != -1) {
        off_t offset = 0;
        size_t remaining = st.st_size;
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            if (sent <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Berikan yield agar thread lain 
                    // bisa jalan jika di satu core
                    sched_yield();
                    continue;
                }
                break; // Error atau koneksi terputus
            }
            if (sent == 0) break; // Client menutup koneksi tengah jalan
            remaining -= sent;
        }
        close(fd);
    }
    free(safe_file_path);
}

/********************************************************************
 * handle_post_request()
 * ANALOGI :
 * Loket penerima BERKAS dari pelanggan.
 *
 * Tamu menyerahkan:
 * - formulir pendaftaran,
 * - upload foto,
 * - data transaksi.
 *
 * Petugas:
 * 1. Cek tujuan valid
 * 2. Pilih dapur pemroses:
 *      - PHP?
 *      - Rust?
 * 3. Data dialirkan bertahap seperti selang air,
 *    tidak ditumpuk dulu agar hemat tenaga.
 * 4. Balasan dari dapur dikirim lagi ke tamu.
 ********************************************************************/
void handle_post_request(int sock_client, RequestHeader *req) {
    // 1. Cek tujuan valid: Validasi Path dulu sebelum komunikasi ke backend
    char *safe_file_path = sanitize_path(config.document_root, req->uri);
    if (safe_file_path == NULL) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    // 2. Pilih dapur pemroses: PHP atau Rust?
    // Tentukan target IP & Port berdasarkan ekstensi
    const char *t_ip;
    int t_port;

    if (strstr(req->uri, ".php")) {
        t_ip = config.php_server;
        t_port = config.php_port;
    } else if (strstr(req->uri, config.rust_ext)) {
        t_ip = config.rust_server;
        t_port = config.rust_port;
    } else {
        // Jika bukan script, tolak POST (karena file statis nggak bisa di-POST)
        send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>POST only for scripts</h1>", req->is_keep_alive);
        free(safe_file_path);
        return;
    }

    // 3. Panggil Modul Unified Streaming 
    // Data dialirkan bertahap seperti selang air,
    // tidak ditumpuk dulu agar hemat tenaga.
    FastCGI_Response res = cgi_request_stream(
        t_ip, 
        t_port, 
        sock_client,
        req->method, 
        req->uri, 
        req->query_string, 
        req->body_data, 
        req->body_length, 
        req->content_length, 
        req->content_type
    );

    // 4. Balasan dari dapur (Rust/PHP) dikirim lagi ke tamu (browser).
    // Kirim Balasan ke Browser jika ada respon
    if (res.body) {
        char header[512];
        int h_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Server: Halmos-Core\r\n"
            "Connection: %s\r\n\r\n",
            strlen(res.body), req->is_keep_alive ? "keep-alive" : "close");
        
        send(sock_client, header, h_len, 0);
        send(sock_client, res.body, strlen(res.body), 0);
        
        if(res.header) free(res.header);
        free(res.body);
    } else {
        send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>Backend Down</h1>", req->is_keep_alive);
    }

    free(safe_file_path);
}

/********************************************************************
 * handle_method()
 * ANALOGI :
 * Manajer front office / pengarah lalu lintas tamu.
 *
 * Dia hanya memutuskan:
 * - Tamu mau ngobrol lama?      → jalur WebSocket
 * - Tamu cuma melihat?          → kirim ke pelayan GET
 * - Tamu kirim berkas?          → kirim ke loket POST
 * - Metode aneh?                → satpam tolak (405)
 *
 * Manajer ini tidak mengerjakan detail,
 * hanya menunjuk petugas yang tepat.
 ********************************************************************/
void handle_method(int sock_client, RequestHeader req_header) {
    // 1. Tamu mau ngobrol lama? → jalur WebSocket
    // Ini belum diimplementasikan ya?
    if (config.secure_application && req_header.is_upgrade) {
        // ... logika websocket ...
        return;
    }

    // 2. Tamu cuma melihat? → kirim ke pelayan GET
    // Cuma melihat ini maksudnya tidak melampirkan berkas (foto, pdf, dll.)
    if (strcmp(req_header.method, "GET") == 0) {
        handle_get_request(sock_client, &req_header); // Pindah ke sini
    } 
    // 3. Tamu kirim berkas? → kirim ke loket POST
    else if (strcmp(req_header.method, "POST") == 0) {
        handle_post_request(sock_client, &req_header);
    } 
    // 4. Metode aneh? tidak dikenal? → satpam tolak (405)
    else {
        send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>", req_header.is_keep_alive);
    }
}