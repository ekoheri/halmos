#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_response.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi.h"
#include "halmos_log.h"

/* Standard C Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

/* System & File I/O */
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <regex.h>

/* System Types & Stats */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

/* Networking Libraries */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Zero-Copy / Advanced I/O */
#include <sys/sendfile.h>

void send_directory_listing(int sock_client, const char *path, const char *uri);

void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive);

void send_halmos_response(int sock_client, HalmosResponse res, bool keep_alive) {
    // 1. Kirim dulu label paket/kop surat/amplop (panggil send_http1_headers)
    send_http1_headers(sock_client, &res, keep_alive);

    // 2. Kalau surat ada isinya → kirim isinya
    if (res.type == RES_TYPE_MEMORY && res.content != NULL && res.length > 0) {
        send(sock_client, res.content, res.length, 0);
    }
}

void send_mem_response(int client_fd, int status_code, const char *status_text, 
                       const char *content, bool keep_alive) {
    HalmosResponse res = {
        .type = RES_TYPE_MEMORY,
        .status_code = status_code,
        .status_message = status_text,
        .mime_type = "text/html",
        .content = (void*)content,
        .length = content ? strlen(content) : 0
    };
    
    send_halmos_response(client_fd, res, keep_alive);
    write_log("[RESPONSE] Status: %d %s | Type: Memory | Keep-Alive: %s", 
              status_code, status_text, keep_alive ? "YES" : "NO");
}

void process_request_routing(int sock_client, RequestHeader *req) {
    const char *target_ip = NULL;
    int target_port = 0;
    if (has_extension(req->uri, ".php")) {
        target_ip = config.php_server;   // Misal "127.0.0.1"
        target_port = config.php_port; // Misal 9000
    } else if (has_extension(req->uri, config.rust_ext)) {
        target_ip = config.rust_server;
        target_port = config.rust_port;
    } else if (has_extension(req->uri, config.python_ext)) {
        target_ip = config.python_server;
        target_port = config.python_port;
    }

    // Jika target ditemukan, jalankan FastCGI
    if (target_ip && target_port > 0) {
        // 1. Jalankan stream (Data langsung dikirim ke client via splice di dalam fungsi ini)
        int status = halmos_fcgi_request_stream(
            req, sock_client, target_ip, target_port,
            req->body_data, req->body_length, req->content_length);

        // 2. Cek statusnya
        if (status != 0) {
            // Jika gagal (status -1), baru kirim error 502
            // Pastikan halmos_fcgi_splice_response belum sempat kirim header apa-apa
            send_mem_response(sock_client, 502, "Bad Gateway", 
                "<h1>502 Bad Gateway</h1><p>Backend Service is Down.</p>", req->is_keep_alive);
        } else if (status == 0) {
            // TAMBAHKAN LOG SUKSES FASTCGI
            write_log("[RESPONSE] 200 OK | FastCGI Stream: %s -> %s:%d", 
                      req->uri, target_ip, target_port);
        }
        return;
    }

    // 2. CEK: Apakah ini Folder? (Untuk Directory Listing atau Index Discovery)
    const char *active_root = get_active_root(req->host);
    char full_path[1024];
    // Gabungkan path (logika seperti di dynamic_response Anda)
    snprintf(full_path, sizeof(full_path), "%s%s", active_root, req->uri);

    struct stat st;
    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // Coba cari index.html
        char index_path[1100];
        snprintf(index_path, sizeof(index_path), "%s%sindex.html", full_path, 
                 (full_path[strlen(full_path)-1] == '/' ? "" : "/"));
        
        if (access(index_path, F_OK) == 0) {
            // Jika ada index.html, update URI dan kirim sebagai static
            // FIX BUG 5: Jangan pakai strcat(req->uri, ...) karena rawan overflow
            char tmp_uri[1024];
            snprintf(tmp_uri, sizeof(tmp_uri), "%s%sindex.html", req->uri, 
                     (req->uri[strlen(req->uri)-1] == '/' ? "" : "/"));
            
            // Simpan pointer asli, pinjamkan pointer tmp_uri ke static_response
            char *original_uri = req->uri;
            req->uri = tmp_uri;
            
            static_response(sock_client, req);
            
            // Kembalikan ke pointer asli agar tidak error saat free() di luar
            req->uri = original_uri; 
            return;
        } else {
            // Jika tidak ada index, baru tampilkan Directory Listing
            send_directory_listing(sock_client, full_path, req->uri);
            return;
        }
    } else {
        // 3. JALUR TERAKHIR: Kirim sebagai file statis biasa
        if (strcmp(req->method, "GET") == 0) {
            static_response(sock_client, req);
        } else {
            send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>", req->is_keep_alive);
        }
    }
}

void static_response(int sock_client, RequestHeader *req) {
    const char *active_root = get_active_root(req->host);
    char *safe_path = sanitize_path(active_root, req->uri);

    if (!safe_path) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    struct stat st;
    if (stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        free(safe_path); 
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd != -1) {
        // Optimasi Socket
        int state = 1;
        setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));

        char header[1024];
        int h_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
            "Server: Halmos-Savage\r\nConnection: %s\r\n"
            "X-Content-Type-Options: nosniff\r\n\r\n",
            get_mime_type(req->uri), st.st_size, req->is_keep_alive ? "keep-alive" : "close");
        
        send(sock_client, header, h_len, MSG_NOSIGNAL);

        off_t offset = 0;
        size_t remaining = st.st_size;
        
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd = { .fd = sock_client, .events = POLLOUT };
                    // FIX BUG 3: Turunkan ke 100ms
                    if (poll(&pfd, 1, 100) > 0) continue; 
                    else break; 
                } else if (errno == EINTR) continue;
                else break; 
            } else if (sent == 0) break;
            remaining -= (size_t)sent;
        }
        close(fd);
    }
    free(safe_path);
}

void dynamic_response(int sock_client, RequestHeader *req) {
    const char *active_root = get_active_root(req->host);
    char full_path[1024];

    // FIX BUG 4: Cek Truncation
    int path_len = snprintf(full_path, sizeof(full_path), "%s%s", active_root, req->uri);
    if (path_len >= (int)sizeof(full_path)) {
        send_mem_response(sock_client, 414, "URI Too Long", "<h1>414 Request-URI Too Long</h1>", req->is_keep_alive);
        return;
    }

    struct stat st;
    if (stat(full_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char index_path[1100];
            snprintf(index_path, sizeof(index_path), "%s%sindex.html", full_path, 
                     (full_path[strlen(full_path)-1] == '/' ? "" : "/"));
            
            if (access(index_path, F_OK) == 0) {
                // Jangan strcat ke req->uri (Bisa leak/overflow)
                // Langsung lempar ke static_response dengan URI baru sementara
                char tmp_uri[1024];
                snprintf(tmp_uri, sizeof(tmp_uri), "%s%sindex.html", req->uri, 
                         (req->uri[strlen(req->uri)-1] == '/' ? "" : "/"));
                
                // Backup URI lama, ganti dengan yang ada index.html
                char *old_uri = req->uri;
                req->uri = tmp_uri;
                static_response(sock_client, req);
                req->uri = old_uri; // Kembalikan agar free() di luar tidak crash
                return;
            } else {
                send_directory_listing(sock_client, full_path, req->uri);
                return;
            }
        }
    }
}

/*
FUNGSI HELPER
*/

void send_directory_listing(int sock_client, const char *path, const char *uri) {
    DIR *d = opendir(path);
    if (!d) {
        send_mem_response(sock_client, 403, "Forbidden", "<h1>403 Forbidden</h1>", false);
        return;
    }

    // 1. Kirim Header HTTP murni
    char header[512];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Server: Halmos-Savage-Server\r\n"
        "Connection: close\r\n\r\n");
    send(sock_client, header, h_len, 0);

    // 2. Kirim Pembuka HTML (Gunakan strlen untuk menghitung panjangnya)
    const char *html_start = "<html><head><style>"
                             "body{font-family:sans-serif; padding:20px;}"
                             "table{width:100%%; border-collapse:collapse;}"
                             "th,td{text-align:left; padding:8px; border-bottom:1px solid #ddd;}"
                             "tr:hover{background-color:#f5f5f5;}"
                             "</style></head><body>";
    send(sock_client, html_start, strlen(html_start), 0);

    char title[1024];
    int t_len = snprintf(title, sizeof(title), "<h1>Index of %s</h1><hr><table>"
                                               "<tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>", uri);
    send(sock_client, title, t_len, 0);

    // 3. Loop Isi Folder (Streaming per baris)
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0) continue;

        struct stat st;
        char full_item_path[1024];
        snprintf(full_item_path, sizeof(full_item_path), "%s/%s", path, dir->d_name);
        
        char size_buf[32] = "-";
        char time_buf[64] = "-";

        if (stat(full_item_path, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                snprintf(size_buf, sizeof(size_buf), "%lld KB", (long long)st.st_size / 1024);
            }
            strftime(time_buf, sizeof(time_buf), "%d-%b-%Y %H:%M", localtime(&st.st_mtime));
        }

        char entry[2048];
        int e_len = snprintf(entry, sizeof(entry), 
            "<tr><td><a href=\"%s%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>",
            uri, (uri[strlen(uri)-1] == '/' ? "" : "/"), dir->d_name,
            dir->d_name, (S_ISDIR(st.st_mode) ? "/" : ""), 
            size_buf, time_buf);
        
        send(sock_client, entry, e_len, 0);
    }
    closedir(d);

    // 4. Kirim Penutup
    const char *html_end = "</table><hr><i>Halmos Savage Engine v2.1</i></body></html>";
    send(sock_client, html_end, strlen(html_end), 0);
}

void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive) {
    // Perbesar ke 1024 supaya aman saat nambah banyak header security
    char header[1024]; 
    const char *conn_status = keep_alive ? "keep-alive" : "close";

    // Gunakan snprintf untuk mencegah buffer overflow
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Server: Halmos-Engine/1.0\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n" // Opsi: Bagus untuk dynamic content
        "\r\n", 
        res->status_code, res->status_message, 
        res->mime_type, res->length, conn_status);
    
    // Jika len >= sizeof(header), berarti ada data yang terpotong
    if (len >= (int)sizeof(header)) {
        write_log("[ERROR http1_response.c] Headers too long, truncated!");
    }

    send(client_fd, header, len, MSG_NOSIGNAL);
}
