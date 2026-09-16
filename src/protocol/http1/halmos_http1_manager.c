#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http1_parser.h"
#include "halmos_http1_response.h"
#include "halmos_http_vhost.h"
#include "halmos_http_utils.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"
#include "halmos_fcgi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stddef.h>

static ssize_t halmos_recv(int fd, void *buf, size_t len, bool is_tls, SSL *ssl_conn) {
    if (is_tls) {
        if (!ssl_conn) return -1;
        return SSL_read(ssl_conn, buf, (int)len);
    }
    return recv(fd, buf, len, 0);
}

static void update_header_pointers(RequestHeader *req, ptrdiff_t diff) {
    if (req->uri)          req->uri += diff;
    if (req->directory)    req->directory += diff;
    if (req->query_string) req->query_string += diff;
    if (req->host)         req->host += diff;
    if (req->content_type) req->content_type += diff;
    if (req->cookie_data)  req->cookie_data += diff;
    if (req->body_data)    req->body_data = (void*)((char*)req->body_data + diff);
    if (req->path_info)    req->path_info += diff;
}

void http1_session_destroy(void *session) {
    HTTP1Session *s = (HTTP1Session *)session;
    if (!s) return;
    if (s->buffer) free(s->buffer);
    if (s->file_fd >= 0) close(s->file_fd);
    http1_parser_free_memory(&s->req);
    free(s);
}

int http1_manager_session(halmos_conn_t *conn) {
    if (!conn->protocol_session) {
        HTTP1Session *s = calloc(1, sizeof(HTTP1Session));
        s->buf_capacity = (config.request_buffer_size > 0) ? config.request_buffer_size : 8192;
        s->buffer = malloc(s->buf_capacity);
        if (s->buffer) s->buffer[0] = '\0';
        s->state = STATE_READ_HEADERS;
        s->file_fd = -1;
        conn->protocol_session = s;
        conn->protocol_session_destroy = http1_session_destroy;
    }
    
    HTTP1Session *session = (HTTP1Session *)conn->protocol_session;
    int sock_client = conn->fd;
    bool is_tls = (conn->ssl != NULL);

    // =========================================================================
    // 1. STATE: BACA HEADER
    // =========================================================================
    if (session->state == STATE_READ_HEADERS) {
        bool should_retry = false;
        bool connection_closed = false;

        while (1) {
            if (session->buf_len >= session->buf_capacity - 1) {
                size_t new_cap = session->buf_capacity * 2;
                char *new_buf = realloc(session->buffer, new_cap);
                if (!new_buf) return -1;
                
                if (new_buf != session->buffer) {
                    update_header_pointers(&session->req, new_buf - session->buffer);
                }
                session->buffer = new_buf;
                session->buf_capacity = new_cap;
            }

            size_t to_read = session->buf_capacity - session->buf_len - 1;
            ssize_t n = halmos_recv(sock_client, session->buffer + session->buf_len, to_read, is_tls, conn->ssl);
            
            if (n > 0) {
                session->buf_len += n;
                session->buffer[session->buf_len] = '\0';
                
                if (strstr(session->buffer, "\r\n\r\n") != NULL) {
                    break; 
                }
            } else if (n < 0) {
                if (is_tls) {
                     int err = SSL_get_error(conn->ssl, (int)n);
                     if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                         should_retry = true;
                     }
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                     should_retry = true;
                }
                break;
            } else { // n == 0
                connection_closed = true;
                break;
            }
        }

        if (connection_closed && session->buf_len == 0) return 0;

        if (strstr(session->buffer, "\r\n\r\n") == NULL) {
            if (connection_closed) return 0;
            if (should_retry) return 2; // WANT_READ (EPOLLIN)
            return -1;
        }

        session->req.is_tls = is_tls;
        
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(sock_client, (struct sockaddr*)&addr, &addr_len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s_addr = (struct sockaddr_in *)&addr;
                inet_ntop(AF_INET, &s_addr->sin_addr, session->req.client_ip, sizeof(session->req.client_ip));
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *)&addr;
                inet_ntop(AF_INET6, &s_addr->sin6_addr, session->req.client_ip, sizeof(session->req.client_ip));
            }
        }

        if (!http1_parser_parse_header(session->buffer, session->buf_len, &session->req) || !session->req.is_valid) {
            http1_response_send_mem(sock_client, 400, "Bad Request", "400 Bad Request", false, is_tls);
            return 0;
        }

        if (session->req.content_length > 0) {
            session->state = STATE_READ_BODY;
        } else {
            session->state = STATE_HANDLE_REQUEST;
        }
    }

    // =========================================================================
    // 1B. STATE: BACA BODY REQUEST
    // =========================================================================
    if (session->state == STATE_READ_BODY) {
        size_t header_len = (char*)session->req.body_data - session->buffer;
        session->req.body_length = session->buf_len - header_len;

        while (session->req.body_length < (size_t)session->req.content_length) {
            if (session->buf_len >= session->buf_capacity - 1) {
                size_t new_cap = session->buf_capacity * 2;
                char *new_buf = realloc(session->buffer, new_cap);
                if (!new_buf) return -1;

                if (new_buf != session->buffer) {
                    update_header_pointers(&session->req, new_buf - session->buffer);
                }
                session->buffer = new_buf;
                session->buf_capacity = new_cap;
            }

            size_t to_read = session->buf_capacity - session->buf_len - 1;
            ssize_t n = halmos_recv(sock_client, session->buffer + session->buf_len, to_read, is_tls, conn->ssl);

            if (n > 0) {
                session->buf_len += n;
                session->buffer[session->buf_len] = '\0';
                session->req.body_length = session->buf_len - header_len;
            } else if (n < 0) {
                if (is_tls) {
                    int err = SSL_get_error(conn->ssl, (int)n);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 2;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 2;
                }
                return -1;
            } else {
                return 0;
            }
        }

        session->state = STATE_HANDLE_REQUEST;
    }
        
    // =========================================================================
    // 2. STATE: HANDLE REQUEST & PREPARE RESPONSE
    // =========================================================================
    if (session->state == STATE_HANDLE_REQUEST) {
        int backend_type = -1;
        if (has_extension(session->req.uri, session->req.path_info, ".php")) backend_type = 0;
        else if (has_extension(session->req.uri, session->req.path_info, config.rust.ext)) backend_type = 1;
        else if (has_extension(session->req.uri, session->req.path_info, config.python.ext)) backend_type = 2;

        if (backend_type != -1) {
            fcgi_api_request_stream(&session->req, sock_client, backend_type, session->req.body_data, session->req.content_length);
            http1_parser_free_memory(&session->req);
            memset(&session->req, 0, sizeof(RequestHeader));
            session->buf_len = 0;
            if (session->buffer) session->buffer[0] = '\0';
            session->state = STATE_READ_HEADERS;
            return 2; // Rearm EPOLLIN
        }

        VHostEntry *vh = (VHostEntry *)session->req.vhost_context;
        const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;
        char *safe_path = sanitize_path(active_root, session->req.uri);
        struct stat st;

        if (!safe_path || stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            if (safe_path) free(safe_path);
            http1_response_send_mem(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", false, is_tls);
            return 0;
        }

        session->file_fd = open(safe_path, O_RDONLY);
        free(safe_path);
        if (session->file_fd == -1) return 0;

        session->file_remaining = st.st_size;
        session->file_offset = 0;
        
        session->header_len = snprintf(session->header_buf, sizeof(session->header_buf),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Server: Halmos-Savage/2.1\r\n"
            "Connection: %s\r\n\r\n",
            get_mime_type(session->req.uri), (long)st.st_size, session->req.is_keep_alive ? "keep-alive" : "close");
        
        session->header_sent_offset = 0;
        session->is_header_sent = false;
        
        // Pindah state ke pengiriman file statis
        session->state = STATE_SEND_STATIC_FILE;
        
        // PENTING: Minta epoll event loop memindah interest socket ke EPOLLOUT!
        return 3; 
    }

    // =========================================================================
    // 3. STATE: PENGIRIMAN FILE STATIS (EPOLLOUT)
    // =========================================================================
    if (session->state == STATE_SEND_STATIC_FILE) {
        int res = is_tls ? http1_manager_ssl_response(conn, session) 
                         : http1_manager_plain_response(sock_client, session);

        // Jika socket belum siap/tersumbat (EAGAIN / EWOULDBLOCK)
        if (res == 3 || res == 2) {
            return res; 
        }

        // Jika terjadi error kirim / connection reset
        if (res <= 0) {
            http1_parser_free_memory(&session->req);
            if (session->file_fd >= 0) {
                close(session->file_fd);
                session->file_fd = -1;
            }
            return 0; 
        }
        
        // Pengiriman Selesai Sukses (res == 1)
        if (session->file_fd >= 0) {
            close(session->file_fd);
            session->file_fd = -1;
        }

        bool keep_alive = session->req.is_keep_alive;
        http1_parser_free_memory(&session->req);
        memset(&session->req, 0, sizeof(RequestHeader));
        
        // Reset total buffer untuk request berikutnya di koneksi keep-alive
        session->buf_len = 0;
        if (session->buffer) session->buffer[0] = '\0';
        session->state = STATE_READ_HEADERS;
        
        // Kembalikan ke EPOLLIN (Status 2) untuk request selanjutnya jika Keep-Alive
        return keep_alive ? 2 : 0;
    }
    
    return 2;
}

int http1_manager_plain_response(int sock_client, HTTP1Session *session) {
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

int http1_manager_ssl_response(halmos_conn_t *conn, HTTP1Session *session) {
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