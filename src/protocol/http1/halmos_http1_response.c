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
#include <sys/sendfile.h>

/********************************************************************
 * 1. HELPER SEND HEADER PLAIN & TLS
 * Non-blocking memory send dengan MSG_NOSIGNAL
 ********************************************************************/
static ssize_t halmos_send_mem(int fd, const void *buf, size_t len, bool is_tls);

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

int http1_response_plain(int sock_client, HTTP1Session *session) {
    // 1. Kirim HTTP Header
    if (!session->is_header_sent) {
        while (session->header_sent_offset < session->header_len) {
            size_t remaining = session->header_len - session->header_sent_offset;
            ssize_t n = send(sock_client, session->header_buf + session->header_sent_offset, remaining, MSG_NOSIGNAL);
            
            if (n > 0) {
                session->header_sent_offset += n;
            } else if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 3;
                return 0;
            } else {
                return 0;
            }
        }
        session->is_header_sent = true;
    }

    // 2. Kirim Body via sendfile() Zero-Copy
    if (session->file_fd >= 0 && session->file_remaining > 0) {
        while (session->file_remaining > 0) {
            off_t offset = session->file_offset;
            ssize_t n_sent = sendfile(sock_client, session->file_fd, &offset, session->file_remaining);

            if (n_sent > 0) {
                session->file_offset = offset;
                session->file_remaining -= (size_t)n_sent;
            } else if (n_sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 3;
                return 0;
            } else { 
                if (session->file_remaining > 0) return 0;
                break;
            }
        }
    }

    return 1; // Transmisi Selesai
}

int http1_response_ssl(halmos_conn_t *conn, HTTP1Session *session) {
    SSL *ssl = conn->ssl;
    if (!ssl) return -1;

    // 1. Kirim Header via TLS
    if (!session->is_header_sent) {
        while (session->header_sent_offset < session->header_len) {
            size_t remaining = session->header_len - session->header_sent_offset;
            int n = SSL_write(ssl, session->header_buf + session->header_sent_offset, (int)remaining);
            
            if (n > 0) {
                session->header_sent_offset += n;
            } else {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_WRITE) return 3;
                if (err == SSL_ERROR_WANT_READ)  return 2;
                return 0;
            }
        }
        session->is_header_sent = true;
    }

    // 2. Kirim Body via Chunked SSL_write
    if (session->file_fd >= 0 && session->file_remaining > 0) {
        char chunk[16384];

        while (session->file_remaining > 0) {
            if (lseek(session->file_fd, session->file_offset, SEEK_SET) == (off_t)-1) {
                return 0;
            }

            size_t to_read = (session->file_remaining < sizeof(chunk)) ? session->file_remaining : sizeof(chunk);
            ssize_t n_read = read(session->file_fd, chunk, to_read);

            if (n_read > 0) {
                int n_sent = SSL_write(ssl, chunk, (int)n_read);
                if (n_sent > 0) {
                    session->file_offset += n_sent;
                    session->file_remaining -= n_sent;
                } else {
                    int err = SSL_get_error(ssl, n_sent);
                    if (err == SSL_ERROR_WANT_WRITE) return 3;
                    if (err == SSL_ERROR_WANT_READ)  return 2;
                    return 0;
                }
            } else if (n_read < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 3;
                return 0;
            } else {
                break;
            }
        }
    }

    return 1; // Transmisi Selesai
}

/*
Private Function (Helper)
*/

ssize_t halmos_send_mem(int fd, const void *buf, size_t len, bool is_tls) {
    if (is_tls) {
        return ssl_send(fd, buf, len);
    }
    return send(fd, buf, len, MSG_NOSIGNAL);
}
