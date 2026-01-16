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

#include "../include/protocols/common/http_utils.h"
#include "../include/protocols/common/http_common.h"
#include "../include/protocols/http1/http1_parser.h"
#include "../include/protocols/http1/http1_response.h"

#include "../include/handlers/fastcgi.h"
#include "../include/handlers/multipart.h"

#define BUFFER_SIZE 1024

extern Config config;

extern TaskQueue global_queue;

/**
 * Fungsi internal (static) untuk membedah baris pertama HTTP (Method & URI)
 */
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

/**
 * Fungsi Utama Parser
 */
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

    // --- LOG RESOURCE DISINI ---
    write_log("Thread Monitoring | Active: %d/%d | Request: %s | Method: %s", 
          global_queue.active_workers, 
          global_queue.total_workers, 
          req->uri, 
          req->method);

    // 2. Cek apakah ini file PHP
    if (strstr(req->uri, ".php")) {
        // Panggil fungsi FastCGI yang kita buat di fpm.c
        // Catatan: Anda mungkin perlu membagi URI menjadi directory dan script_name
        FastCGI_Response res = fastcgi_request(
            config.php_server,
            config.php_port,
            "",                     // directory (sesuaikan jika ada subfolder)
            req->uri,               // script_name
            req->method, 
            req->query_string ? req->query_string : "",
            "",                     // path_info
            "",                     // post_data (GET biasanya kosong)
            ""                      // content_type
        );

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

            // Bebaskan memori yang dialokasikan fpm.c
            if (res.header) free(res.header);
            if (res.body) free(res.body);
        } else {
            send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>504 Gateway Timeout</h1>", req->is_keep_alive);
        }
        
        free(safe_file_path);
        return; // Keluar agar tidak lanjut ke pengiriman file statis
    }

    // 3. Logika pemanggilan Rust
    if (strstr(req->uri, config.rust_ext)) {
        // 1. Bersihkan path (Sudah benar)
        char clean_path[PATH_MAX];
        memset(clean_path, 0, sizeof(clean_path));
        int j = 0;
        for (int i = 0; req->uri[i] != '\0' && i < PATH_MAX - 1; i++) {
            if (req->uri[i] == '/' && req->uri[i+1] == '/') continue;
            clean_path[j++] = req->uri[i];
        }
        clean_path[j] = '\0';

        // 2. Panggil Rust
        FastCGI_Response res_rust = fastcgi_request(
            config.rust_server, config.rust_port, "", clean_path, 
            req->method, req->query_string ? req->query_string : "", "", "", ""
        );

        if (res_rust.body != NULL) {
            // --- LOGIKA PERBAIKAN PENGIRIMAN HEADER ---
            
            // A. Kirim Status Line (Wajib Pertama)
            send(sock_client, "HTTP/1.1 200 OK\r\n", 17, 0);

            // B. Kirim Header tambahan dari Server C (Kirim SEBELUM header Rust ditutup)
            char len_header[64];
            snprintf(len_header, sizeof(len_header), "Content-Length: %zu\r\n", strlen(res_rust.body));
            send(sock_client, "Server: Halmos-Core\r\n", 21, 0);
            send(sock_client, "Connection: keep-alive\r\n", 24, 0);
            send(sock_client, len_header, strlen(len_header), 0);

            // C. Kirim Header dari Rust
            // Berdasarkan log, res_rust.header berisi "Content-Type: text/html\r\n\r\n"
            if (res_rust.header != NULL) {
                send(sock_client, res_rust.header, strlen(res_rust.header), 0);
            } else {
                // Jika Rust tidak kirim header sama sekali, kita wajib tutup headernya di sini
                send(sock_client, "Content-Type: text/html\r\n\r\n", 27, 0);
            }

            // D. Kirim Body
            send(sock_client, res_rust.body, strlen(res_rust.body), 0);

            // Bersihkan memori
            if (res_rust.header) free(res_rust.header);
            if (res_rust.body) free(res_rust.body);
        } else {
            send_mem_response(sock_client, 504, "Gateway Timeout", "<h1>504 Gateway Timeout</h1>", req->is_keep_alive);
        }
        free(safe_file_path);
        return;
    }
    // 4. Logika File Statis
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
                    //usleep(1000); // Tunggu buffer socket kosong
                    // Berikan yield agar thread lain bisa jalan jika di satu core
                    sched_yield();
                    continue;
                }
                break; // Error atau koneksi terputus
            }
            //remaining -= sent;
            if (sent == 0) break; // Client menutup koneksi tengah jalan
            remaining -= sent;
        }
        close(fd);
    }
    free(safe_file_path);
}

void handle_post_request(int sock_client, RequestHeader *req) {
    // Jika ada data multipart (Upload file atau Form)
    if (req->parts_count > 0) {
        bool upload_success = false;
        
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].filename) {
                // Simpan file ke folder uploads
                if (save_uploaded_file(&req->parts[i], "uploads")) {
                    upload_success = true;
                }
            }
        }

        if (upload_success) {
            send_mem_response(sock_client, 201, "Created", "<h1>File Berhasil Diupload!</h1>", req->is_keep_alive);
        } else {
            send_mem_response(sock_client, 200, "OK", "<h1>Form Data Diterima</h1>", req->is_keep_alive);
        }
    } 
    // Jika hanya POST body biasa (Plain text / JSON)
    else if (req->body_data) {
        write_log("Data POST diterima: %s", (char*)req->body_data);
        send_mem_response(sock_client, 200, "OK", "<h1>Data POST Diterima</h1>", req->is_keep_alive);
    } else {
        send_mem_response(sock_client, 400, "Bad Request", "<h1>Empty POST body</h1>", req->is_keep_alive);
    }
}

void handle_method(int sock_client, RequestHeader req_header) {
    // Jalur WebSocket
    if (config.secure_application && req_header.is_upgrade) {
        // ... logika websocket ...
        return;
    }

    // Jalur GET (File Statis)
    if (strcmp(req_header.method, "GET") == 0) {
        handle_get_request(sock_client, &req_header); // Pindah ke sini
    } 
    // Jalur POST (Upload/Data)
    else if (strcmp(req_header.method, "POST") == 0) {
        handle_post_request(sock_client, &req_header);
    } 
    else {
        send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>", req_header.is_keep_alive);
    }
}