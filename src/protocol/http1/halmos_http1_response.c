#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_response.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_http1_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <netinet/in.h>  // Untuk IPPROTO_TCP
#include <netinet/tcp.h> // Untuk TCP_NODELAY

/* * CATATAN: Fungsi halmos_send dan proses SSL_write 
 * sekarang sudah dipindah ke Manager sesuai instruksi Boss. 
 * File ini fokus pada pengiriman Plaintext & Zero-Copy.
 */

/********************************************************************
 * 1. SEND HTTP HEADERS (PLAIN)
 ********************************************************************/
static void send_headers_plain(int client_fd, int status, const char *msg, const char *mime, size_t len, bool ka) {
    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\nServer: Halmos-Savage/2.1\r\n\r\n",
        status, msg, mime, len, ka ? "keep-alive" : "close");
    
    send(client_fd, header, h_len, MSG_NOSIGNAL);
}

/********************************************************************
 * 2. MEMORY RESPONSE (PLAIN)
 ********************************************************************/
void http1_response_send_mem(int client_fd, int status_code, const char *status_text, 
                            const char *content, bool keep_alive) {
    size_t len = content ? strlen(content) : 0;
    send_headers_plain(client_fd, status_code, status_text, "text/html", len, keep_alive);
    if (len > 0) {
        send(client_fd, content, len, MSG_NOSIGNAL);
    }
}

/********************************************************************
 * 3. STATIC RESPONSE (ZERO-COPY STRATEGY)
 * Hanya dipanggil oleh Manager jika req->is_tls == false
 ********************************************************************/
void http1_response_zerocopy(int sock_client, RequestHeader *req, VHostEntry *vh) {
    const char *active_root = (vh) ? vh->root : config.document_root;

    // Sanitize path adalah WAJIB sebelum stat atau open
    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    if (!safe_path || stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        http1_response_send_mem(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        if (safe_path) free(safe_path);
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        http1_response_send_mem(sock_client, 500, "Internal Error", "<h1>500</h1>", false);
        free(safe_path);
        return;
    }

    // TCP Optimization untuk Zero-Copy
    int state = 1;
    setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));

    // Kirim Header Plain
    send_headers_plain(sock_client, 200, "OK", get_mime_type(req->uri), st.st_size, req->is_keep_alive);

    // SENDFILE: Data pindah dari Disk ke Socket langsung di level Kernel
    
    off_t offset = 0;
    size_t remaining = st.st_size;
    while (remaining > 0) {
        ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
        if (sent <= 0) {
            if (errno == EAGAIN || errno == EINTR) {
                struct pollfd pfd = { .fd = sock_client, .events = POLLOUT };
                poll(&pfd, 1, 100);
                continue;
            }
            break;
        }
        remaining -= (size_t)sent;
    }

    close(fd);
    free(safe_path);
}

/********************************************************************
 * 4. DIRECTORY LISTING (PLAIN)
 ********************************************************************/
static void send_directory_listing_plain(int sock_client, const char *path, const char *uri) {
    DIR *d = opendir(path);
    if (!d) return;

    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
                    "<html><body><h1>Index of ";
    send(sock_client, h, strlen(h), 0);
    send(sock_client, uri, strlen(uri), 0);
    send(sock_client, "</h1><hr><ul>", 13, 0);

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        char entry[1024];
        int e_len = snprintf(entry, sizeof(entry), "<li><a href=\"%s/%s\">%s</a></li>", 
                             uri, dir->d_name, dir->d_name);
        send(sock_client, entry, e_len, 0);
    }
    send(sock_client, "</ul></body></html>", 20, 0);
    closedir(d);
}

/********************************************************************
 * 5. PROCESS REQUEST ROUTING
 * Memisahkan takdir: SSL ke Manager, Plain ke Zero-Copy
 ********************************************************************/

void http1_response_routing(int sock_client, RequestHeader *req) {
    int backend_type = -1; // -1 berarti bukan FastCGI

    // 1. IDENTIFIKASI GRUP BACKEND BERDASARKAN EKSTENSI
    if (has_extension(req->uri, req->path_info, ".php")) { 
        backend_type = 0; // PHP
    } 
    else if (has_extension(req->uri, req->path_info, config.rust.ext)) { 
        backend_type = 1; // Rust
    } 
    else if (has_extension(req->uri, req->path_info, config.python.ext)) { 
        backend_type = 2; // Python
    }

    // 2. JALUR FASTCGI (Delegasikan pemilihan Node ke API Request Stream)
    if (backend_type != -1) {
        /* KITA TIDAK KIRIM IP/PORT LAGI DISINI.
           Kita kirim backend_type, biar di dalam sana Halmos melakukan Load Balancing.
           Note: Jika fungsi api kamu masih butuh signature lama, kita kirim NULL & backend_type.
        */
        fcgi_api_request_stream(req, sock_client, backend_type, req->body_data, req->content_length);
        return;
    }

    // 2. JALUR TLS (Hanya untuk File Statis, karena PHP sudah di-handle di atas)
    if (req->is_tls) {
        //fprintf(stderr, "[ROUTING DEBUG] Memanggil http1_manager_ssl_response untuk file statis...\n");
        http1_manager_ssl_response(sock_client, req); 
        return;
    }

    // DAPATKAN KONTEKS VHOST
    // Kita panggil context-nya di sini untuk menentukan root folder yang aktif.
    VHostEntry *vh = http_vhost_get_context(req->host);
    const char *active_root = (vh) ? vh->root : config.document_root;

    // 3. AMANKAN PATH DIREKTORI
    char *safe_dir_path = sanitize_path(active_root, req->directory);
    if (!safe_dir_path) {
        http1_response_send_mem(sock_client, 403, "Forbidden", "<h1>403 Forbidden</h1>", false);
        return;
    }

    struct stat st;
    if (stat(safe_dir_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char index_check[PATH_MAX];
        
        // Cek index.html menggunakan path yang sudah disanitasi
        snprintf(index_check, sizeof(index_check), "%s/index.html", safe_dir_path);
        if (access(index_check, F_OK) == 0) {
            strcat(req->uri, "index.html"); 
            http1_response_zerocopy(sock_client, req, vh); // Oper vh
            free(safe_dir_path);
            return;
        }

        // Cek index.php
        snprintf(index_check, sizeof(index_check), "%s/index.php", safe_dir_path);
        if (access(index_check, F_OK) == 0) {
            strcat(req->uri, "index.php");
            free(safe_dir_path);
            http1_response_routing(sock_client, req); // Rekursif aman
            return;
        }

        send_directory_listing_plain(sock_client, safe_dir_path, req->uri);
        free(safe_dir_path);
        return;
    }

    // 4. Static File
    if (safe_dir_path) free(safe_dir_path);
    http1_response_zerocopy(sock_client, req, vh); // Oper vh
}
