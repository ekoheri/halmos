#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>  // Wajib untuk fungsi send()
#include <unistd.h>      // Wajib untuk fungsi close() jika ada

#include "http1_handler.h"
#include "http1_response.h"
#include "fastcgi.h"
#include "uwsgi_handler.h"
#include "config.h"
#include "http_utils.h"

extern Config config;

/********************************************************************
 * handle_dynamic_request()
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
 *      - Python?
 * 3. Data dialirkan bertahap seperti selang air,
 *    tidak ditumpuk dulu agar hemat tenaga.
 * 4. Balasan dari dapur dikirim lagi ke tamu.
 ********************************************************************/
void handle_dynamic_request(int sock_client, RequestHeader *req) {
    const char *target_ip;
    int target_port;
    bool is_uwsgi = false;

    // 1. Pilih Backend berdasarkan Ekstensi
    if (has_extension(req->uri, ".php")) {
        target_ip = config.php_server; 
        target_port = config.php_port;
    } else if (has_extension(req->uri, config.rust_ext)) {
        target_ip = config.rust_server; 
        target_port = config.rust_port;
    } else if (has_extension(req->uri, config.python_ext)) {
        target_ip = config.python_server; 
        target_port = config.python_port;
        is_uwsgi = true;
    } else {
        // Keamanan tambahan: Jika masuk ke dynamic_handler tapi ekstensinya nggak dikenal
        send_mem_response(sock_client, 403, "Forbidden", "<h1>Script not allowed</h1>", req->is_keep_alive);
        return;
    }

    // 2. Eksekusi berdasarkan Protokol Backend
    if (is_uwsgi) {
        UWSGI_Response res = uwsgi_request_stream(target_ip, target_port, sock_client,
                                                  req->method, req->uri, req->query_string ? req->query_string : "",
                                                  req->body_data, req->body_length, req->content_length, "");
        if (res.body) {
            char header[1024];
            int h_len = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n"
                "Server: Halmos-Core\r\nConnection: %s\r\n\r\n",
                res.body_len, req->is_keep_alive ? "keep-alive" : "close");
            send(sock_client, header, h_len, 0);
            send(sock_client, res.body, res.body_len, 0);
            free_uwsgi_response(&res);
        }
    } else {
        // Gabungan GET & POST untuk FastCGI (PHP/Rust)
        FastCGI_Response res = cgi_request_stream(target_ip, target_port, sock_client,
                                                  req->method, req->uri, req->query_string, 
                                                  req->body_data, req->body_length, 
                                                  req->content_length, req->content_type, 
                                                  req->cookie_data);
        if (res.body) {
            char http_header[2048]; 
            int status_code = 200;
            const char *status_msg = "OK";

            if (res.header) {
                if (strstr(res.header, "Location:")) {
                    status_code = 302;
                    status_msg = "Found";
                }
            }

            // 1. Isi awal header (Status Line, Server, dll)
            // snprintf balikin jumlah karakter yang ditulis
            int header_len = snprintf(http_header, sizeof(http_header),
                "HTTP/1.1 %d %s\r\n"
                "Server: Halmos-Core\r\n"
                "Content-Length: %zu\r\n"
                "Connection: %s\r\n",
                status_code, status_msg, strlen(res.body), 
                req->is_keep_alive ? "keep-alive" : "close");

            // 2. Tempel header dari PHP kalau ada
            if (res.header) {
                // Kita update current_len-nya
                header_len += snprintf(http_header + header_len, sizeof(http_header) - header_len, 
                                        "%s", res.header);
            }

            // 3. Tambah penutup header \r\n\r\n
            header_len += snprintf(http_header + header_len, sizeof(http_header) - header_len, 
                                    "\r\n\r\n");

            // 4. SEKARANG DIPAKE! current_len dipake di sini biar send() tau persis berapa byte
            send(sock_client, http_header, header_len, 0);
            send(sock_client, res.body, strlen(res.body), 0);

            if (res.header) free(res.header);
            free(res.body);
        } else {
            send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>Backend Down</h1>", req->is_keep_alive);
        }
    }
}