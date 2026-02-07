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
    // 1. CEK: Apakah ini script dinamis (FastCGI)?
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
            strcat(req->uri, (req->uri[strlen(req->uri)-1] == '/' ? "index.html" : "/index.html"));
            static_response(sock_client, req);
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

    //printf("[DEBUG] Full Path: %s", safe_path);

    if (!safe_path) {
        //printf("[DEBUG] Error Stat: %s (File mungkin tidak ada)\n", safe_file_path);
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    struct stat st;
    if (stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        free(safe_path); return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd != -1) {
        int state = 1;
        // Paksa paket langsung keluar (NODELAY) dan minta ACK cepat (QUICKACK)
        setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
        setsockopt(sock_client, IPPROTO_TCP, TCP_QUICKACK, &state, sizeof(state));

        char header[1024];
        int h_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
            "Server: Halmos-Core\r\nConnection: %s\r\n\r\n",
            get_mime_type(req->uri), st.st_size, req->is_keep_alive ? "keep-alive" : "close");
        
        //send(sock_client, header, h_len, 0);
        send(sock_client, header, h_len, MSG_NOSIGNAL);

        write_log("[RESPONSE] 200 OK | Static: %s | Size: %ld bytes", req->uri, st.st_size);

        off_t offset = 0;
        size_t remaining = st.st_size;
        
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            
            if (sent > 0) {
                remaining -= sent;
            } else if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // C. GANTI: Poll cukup 10ms - 50ms saja. 
                    // Kalau 100ms keburu di-abort sama AB kalau antrean numpuk.
                    struct pollfd pfd = { .fd = sock_client, .events = POLLOUT };
                    if (poll(&pfd, 1, 5000) > 0) continue; 
                    else break; 
                } else if (errno == EINTR) {
                    continue;
                } else {
                    break; 
                }
            } else {
                break;
            }
        }

        // D. Cabut CORK: Paksa kernel kirim paket terakhir (Zero-Latency Finish)
        // printf("[DEBUG] Total Body terkirim: %zu/%ld bytes\n", total_sent, st.st_size);
        //state = 0;
        //setsockopt(sock_client, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

        close(fd);
    }
    free(safe_path);
}

void dynamic_response(int sock_client, RequestHeader req_header) {
    // 1. CEK: Apakah ini script dinamis (FastCGI)?
    // 1. Tentukan Root-nya dulu!
    const char *active_root = get_active_root(req_header.host);

    // 2. Perbaikan URI (tetap seperti kodemu)
    if (req_header.uri[0] != '/') {
        char temp[1024];
        snprintf(temp, sizeof(temp), "/%s", req_header.uri);
        req_header.uri = strdup(temp);
    }
    
    char full_path[1024];
    // PAKAI active_root, JANGAN config.document_root
    if (active_root[strlen(active_root)-1] == '/' && req_header.uri[0] == '/') {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req_header.uri + 1);
    } else {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req_header.uri);
    }

    // DEBUG sekarang jadi akurat
    // printf("[DEBUG] URI: %s | Active Root: %s | Full Path: %s", req_header.uri, active_root, full_path);

    struct stat st;
    if (stat(full_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char index_path[1024+32];
            // Standardisasi path index
            if (full_path[strlen(full_path)-1] == '/') {
                snprintf(index_path, sizeof(index_path), "%sindex.html", full_path);
            } else {
                snprintf(index_path, sizeof(index_path), "%s/index.html", full_path);
            }
            
            if (access(index_path, F_OK) == 0) {
                // Tambahkan index.html ke URI asli buat dilempar ke static/dynamic handler
                if (req_header.uri[strlen(req_header.uri)-1] == '/') {
                    strcat(req_header.uri, "index.html");
                } else {
                    strcat(req_header.uri, "/index.html");
                }
            } else {
                send_directory_listing(sock_client, full_path, req_header.uri);
                // Penting: Free sebelum return!
                if (req_header.uri) free(req_header.uri);
                if (req_header.query_string) free(req_header.query_string);
                if (req_header.cookie_data) free(req_header.cookie_data);
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

    // Header HTML dengan sedikit CSS biar gak kaku banget
    char *body = (char *)malloc(32768); // Alokasi agak besar buat folder rame
    snprintf(body, 32768, 
        "<html><head><title>Index of %s</title>"
        "<style>body{font-family:sans-serif;} table{width:100%%; border-collapse:collapse;} "
        "th,td{text-align:left; padding:8px;} tr:nth-child(even){background:#f2f2f2;}</style>"
        "</head><body><h1>Index of %s</h1><hr><table>"
        "<tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>", uri, uri);

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0) continue;

        struct stat st;
        char full_item_path[1024];
        snprintf(full_item_path, sizeof(full_item_path), "%s/%s", path, dir->d_name);
        stat(full_item_path, &st);

        // Format Waktu
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%d-%b-%Y %H:%M", localtime(&st.st_mtime));

        // Format Ukuran
        char size_buf[32];
        if (S_ISDIR(st.st_mode)) strcpy(size_buf, "-");
        else snprintf(size_buf, sizeof(size_buf), "%lld KB", (long long)st.st_size / 1024);

        char entry[2048];
        snprintf(entry, sizeof(entry), 
            "<tr><td><a href=\"%s%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>",
            uri, (uri[strlen(uri)-1] == '/' ? "" : "/"), dir->d_name,
            dir->d_name, (S_ISDIR(st.st_mode) ? "/" : ""), 
            time_buf, size_buf);
        
        strcat(body, entry);
    }
    closedir(d);
    strcat(body, "</table><hr><i>Halmos Engine v1.0</i></body></html>");
    
    send_mem_response(sock_client, 200, "OK", body, false);
    free(body);
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

    send(client_fd, header, len, 0);
}
