#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_response.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_log.h"
#include "halmos_http1_manager.h"
#include "halmos_sec_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

/********************************************************************
 * 1. HELPER SEND HEADER PLAIN & TLS
 * Non-blocking memory send dengan MSG_NOSIGNAL
 ********************************************************************/
static ssize_t halmos_send_mem(int fd, const void *buf, size_t len, bool is_tls) {
    if (is_tls) {
        return ssl_send(fd, buf, len);
    }
    return send(fd, buf, len, MSG_NOSIGNAL);
}

void http1_response_send_headers(int client_fd, int status, const char *msg, 
                                 const char *mime, size_t len, bool ka, bool is_tls) {
    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Server: Halmos-Savage/2.1\r\n\r\n",
        status, msg, mime, len, ka ? "keep-alive" : "close");
    
    if (h_len > 0) {
        halmos_send_mem(client_fd, header, (size_t)h_len, is_tls);
    }
}

/********************************************************************
 * 2. MEMORY RESPONSE (PLAIN & TLS)
 * Untuk pengiriman respon singkat langsung dari RAM (HTML/JSON/Text)
 ********************************************************************/
void http1_response_send_mem(int client_fd, int status_code, const char *status_text, 
                            const char *content, bool keep_alive, bool is_tls) {
    size_t len = content ? strlen(content) : 0;
    http1_response_send_headers(client_fd, status_code, status_text, "text/html", len, keep_alive, is_tls);
    
    if (len > 0 && content != NULL) {
        halmos_send_mem(client_fd, content, len, is_tls);
    }
}

/********************************************************************
 * 3. DIRECTORY LISTING
 * Aman dari SIGPIPE dan dikirim secara terkontrol
 ********************************************************************/
void http1_response_send_dir_listing(int sock_client, const char *path, const char *uri, bool is_tls) {
    DIR *d = opendir(path);
    if (!d) {
        http1_response_send_mem(sock_client, 403, "Forbidden", "<h1>403 Directory Access Denied</h1>", false, is_tls);
        return;
    }

    // Kirim Header Chunked/Close untuk Directory Listing Dynamic
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nServer: Halmos-Savage/2.1\r\n\r\n"
                    "<!DOCTYPE html><html><head><title>Index of ";
    halmos_send_mem(sock_client, h, strlen(h), is_tls);
    halmos_send_mem(sock_client, uri, strlen(uri), is_tls);
    
    const char *h2 = "</title></head><body><h1>Index of ";
    halmos_send_mem(sock_client, h2, strlen(h2), is_tls);
    halmos_send_mem(sock_client, uri, strlen(uri), is_tls);
    
    const char *h3 = "</h1><hr><ul>";
    halmos_send_mem(sock_client, h3, strlen(h3), is_tls);

    struct dirent *dir;
    char entry[1024];
    while ((dir = readdir(d)) != NULL) {
        // Abaikan "."
        if (strcmp(dir->d_name, ".") == 0) continue;

        int e_len = snprintf(entry, sizeof(entry), "<li><a href=\"%s%s%s\">%s%s</a></li>", 
                             uri, 
                             (uri[strlen(uri) - 1] == '/') ? "" : "/", 
                             dir->d_name, 
                             dir->d_name,
                             (dir->d_type == DT_DIR) ? "/" : "");
        if (e_len > 0) {
            halmos_send_mem(sock_client, entry, (size_t)e_len, is_tls);
        }
    }
    
    const char *footer = "</ul><hr><i>Halmos-Savage/2.1 Server</i></body></html>";
    halmos_send_mem(sock_client, footer, strlen(footer), is_tls);
    
    closedir(d);
}

/********************************************************************
 * 4. STANDARD ERROR RESPONSES
 * Short helper untuk pemanggilan cepat respon HTTP Error
 ********************************************************************/
void http1_response_send_error(int sock_client, int code, bool is_tls) {
    switch (code) {
        case 400:
            http1_response_send_mem(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false, is_tls);
            break;
        case 403:
            http1_response_send_mem(sock_client, 403, "Forbidden", "<h1>403 Forbidden</h1>", false, is_tls);
            break;
        case 404:
            http1_response_send_mem(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", false, is_tls);
            break;
        case 500:
        default:
            http1_response_send_mem(sock_client, 500, "Internal Server Error", "<h1>500 Internal Server Error</h1>", false, is_tls);
            break;
    }
}