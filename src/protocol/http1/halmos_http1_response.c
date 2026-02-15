#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_response.h"
#include "halmos_global.h"
#include "halmos_http1_header.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_config.h"
#include "halmos_security.h" // Supaya get_ssl_for_fd dikenal

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>

/* --- PROTOTYPE INTERNAL --- */
static void send_directory_listing(int sock_client, const char *path, const char *uri);
static void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive);
static ssize_t halmos_send(int fd, const void *buf, size_t len, int flags);

/********************************************************************
 * 1. SEND HALMOS RESPONSE
 * Jalur utama pengiriman data memory-based
 ********************************************************************/
void send_halmos_response(int sock_client, HalmosResponse res, bool keep_alive) {
    send_http1_headers(sock_client, &res, keep_alive);
    if (res.type == RES_TYPE_MEMORY && res.content != NULL && res.length > 0) {
        //halmos_send(sock_client, res.content, res.length, MSG_NOSIGNAL);
        halmos_send(sock_client, res.content, res.length, MSG_NOSIGNAL);
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
}

/********************************************************************
 * 2. STATIC RESPONSE (Savage Performance)
 * Menggunakan sendfile + TCP_QUICKACK
 ********************************************************************/
void static_response(int sock_client, RequestHeader *req) {
    const char *active_root = get_active_root(req->host);
    char *safe_path = sanitize_path(active_root, req->uri);
    if (!safe_path) {
        write_log_error("[STATIC] Path sanitization failed for URI: %s", req->uri);
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    struct stat st;
    if (stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        write_log("[STATIC] 404 Not Found: %s", safe_path);
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        free(safe_path); 
        return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        write_log_error("[ERR] Failed to open file %s: %s", safe_path, strerror(errno));
        send_mem_response(sock_client, 500, "Internal Server Error", "<h1>500</h1>", false);
        free(safe_path);
        return;
    }
    // OPTIMASI TINGKAT DEWA
    int state = 1;
    setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
    setsockopt(sock_client, IPPROTO_TCP, TCP_QUICKACK, &state, sizeof(state));

    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
        "Server: Halmos-Savage/2.1\r\nConnection: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n\r\n",
        get_mime_type(req->uri), st.st_size, req->is_keep_alive ? "keep-alive" : "close");
    
    halmos_send(sock_client, header, h_len, MSG_NOSIGNAL);

    if (config.tls_enabled) {
        // --- JALUR TLS: Read-Encrypt-Write ---
        char *file_buf = malloc(65536); // Chunk 64KB
        ssize_t n_read;
        while ((n_read = read(fd, file_buf, 65536)) > 0) {
            ssize_t total_sent = 0;
            while (total_sent < n_read) {
                ssize_t n_sent = halmos_send(sock_client, file_buf + total_sent, n_read - total_sent, 0);
                if (n_sent <= 0) break;
                total_sent += n_sent;
            }
        }
        free(file_buf);
    } else {
        off_t offset = 0;
        size_t remaining = st.st_size;
        
        // Logika Poll Sabar dari kode lama (mencegah failed request)
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd = { .fd = sock_client, .events = POLLOUT };
                    if (poll(&pfd, 1, 1000) > 0) continue; 
                    else break; 
                } else if (errno == EINTR) continue;
                else break; 
            } else if (sent == 0) break;
            remaining -= (size_t)sent;
        }
    }
    close(fd);
    free(safe_path);
}

/********************************************************************
 * 3. PROCESS REQUEST ROUTING
 * Otak dari penentuan arah request
 ********************************************************************/

void process_request_routing(int sock_client, RequestHeader *req) {
    //fprintf(stderr, "[DEBUG-ROUTING-DECISION] Method: %s | URI: %s\n", req->method, req->uri);
    // A. Scripting (FastCGI)
    const char *target_ip = NULL;
    int target_port = 0;
    if (has_extension(req->uri, req->path_info,".php")) {
        target_ip = config.php_server;
        target_port = config.php_port;
    } else if (has_extension(req->uri, req->path_info, config.rust_ext)) {
        target_ip = config.rust_server;
        target_port = config.rust_port;
    } else if (has_extension(req->uri, req->path_info, config.python_ext)) {
        target_ip = config.python_server;
        target_port = config.python_port;
    }

    if (target_ip && target_port > 0) {
        write_log("[CGI] Proxying %s to %s:%d", req->uri, target_ip, target_port);
        if (halmos_fcgi_request_stream(req, sock_client, target_ip, target_port,
            req->body_data, req->content_length) != 0) {
            write_log_error("[CGI] Backend error on %s:%d for request %s", target_ip, target_port, req->uri);
            send_mem_response(sock_client, 502, "Bad Gateway", "<h1>502 Bad Gateway</h1>", req->is_keep_alive);
        }
        return;
    }

    // B. Folder & Index Discovery
    //const char *active_root = get_active_root(req->host);
    //char full_path[1024];
    //snprintf(full_path, sizeof(full_path), "%s%s", active_root, req->uri);

    char full_path[1024];
    const char *active_root = get_active_root(req->host);

    // Logika: Jika root diakhiri '/' DAN uri diawali '/', buang salah satu
    if (active_root[strlen(active_root)-1] == '/' && req->directory[0] == '/') {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req->directory + 1);
    } else {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req->directory);
    }

    struct stat st;
    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char index_path[1100];
        snprintf(index_path, sizeof(index_path), "%s%sindex.html", full_path, 
                 (full_path[strlen(full_path)-1] == '/' ? "" : "/"));
        
        if (access(index_path, F_OK) == 0) {
            char tmp_uri[1024];
            snprintf(tmp_uri, sizeof(tmp_uri), "%s%sindex.html", req->uri, 
                     (req->uri[strlen(req->uri)-1] == '/' ? "" : "/"));
            
            char *original_uri = req->uri;
            req->uri = tmp_uri;
            static_response(sock_client, req);
            req->uri = original_uri; 
            return;
        } else {
            send_directory_listing(sock_client, full_path, req->uri);
            return;
        }
    }

    // C. Static Files
    if (strcmp(req->method, "GET") == 0) {
        static_response(sock_client, req);
    } else {
        write_log("[HTTP] Method %s not allowed for static files", req->method);
        send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405</h1>", req->is_keep_alive);
    }
}

/********************************************************************
 * 4. DIRECTORY LISTING (Streaming Mode - RAM Efficient)
 ********************************************************************/
void send_directory_listing(int sock_client, const char *path, const char *uri) {
    DIR *d = opendir(path);
    if (!d) {
        send_mem_response(sock_client, 403, "Forbidden", "<h1>403 Forbidden</h1>", false);
        return;
    }

    // Header & CSS
    const char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
                         "<html><head><style>body{font-family:sans-serif;padding:20px;}"
                         "table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid #ddd;}"
                         "</style></head><body><h1>Index of ";
    halmos_send(sock_client, header, strlen(header), 0);
    halmos_send(sock_client, uri, strlen(uri), 0);
    const char *table_start = "</h1><hr><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>";
    halmos_send(sock_client, table_start, strlen(table_start), 0);

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0) continue;
        struct stat st;
        char fpath[4096];
        snprintf(fpath, sizeof(fpath), "%s/%s", path, dir->d_name);
        stat(fpath, &st);

        char entry[2048];
        int e_len = snprintf(entry, sizeof(entry), 
            "<tr><td><a href=\"%s%s%s\">%s%s</a></td><td>%ld KB</td><td>%s</td></tr>",
            uri, (uri[strlen(uri)-1] == '/' ? "" : "/"), dir->d_name,
            dir->d_name, (S_ISDIR(st.st_mode) ? "/" : ""), 
            (long)st.st_size/1024, ctime(&st.st_mtime));
        halmos_send(sock_client, entry, e_len, 0);
    }
    closedir(d);
    const char *footer = "</table><hr><i>Halmos Savage Engine</i></body></html>";
    halmos_send(sock_client, footer, strlen(footer), 0);
}

// HELPER
ssize_t halmos_send(int fd, const void *buf, size_t len, int flags) {
    if (config.tls_enabled) {
        SSL *ssl = get_ssl_for_fd(fd);
        if (!ssl) return -1;

        size_t total_sent = 0;
        while (total_sent < len) {
            int n_sent = SSL_write(ssl, (char*)buf + total_sent, (int)(len - total_sent));
            
            if (n_sent <= 0) {
                int err = SSL_get_error(ssl, n_sent);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                    // Buffer penuh, tunggu sebentar (Savage Mode: Poll)
                    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                    poll(&pfd, 1, 10); // Tunggu 10ms
                    continue;
                }
                return -1; // Real error
            }
            total_sent += n_sent;
        }
        return total_sent;
    }
    // Untuk non-TLS tetap pakai send biasa
    return send(fd, buf, len, flags);
}

/********************************************************************
 * 5. SEND HTTP1 HEADERS
 ********************************************************************/
void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive) {
    char header[1024]; 
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\nServer: Halmos-Savage/2.1\r\n\r\n", 
        res->status_code, res->status_message, res->mime_type, res->length, 
        keep_alive ? "keep-alive" : "close");
    
    //send(client_fd, header, len, MSG_NOSIGNAL);
    halmos_send(client_fd, header, len, MSG_NOSIGNAL);
}