#ifndef HALMOS_HTTP1_RESPONSE_H
#define HALMOS_HTTP1_RESPONSE_H

#include "halmos_http1_manager.h"

#include <stdbool.h>
#include <stddef.h>

void http1_response_send_headers(int client_fd, int status, const char *msg, 
                                 const char *mime, size_t len, bool ka, bool is_tls);

void http1_response_send_mem(int client_fd, int status_code, const char *status_text, 
                            const char *content, bool keep_alive, bool is_tls);

void http1_response_send_dir_listing(int sock_client, const char *path, const char *uri, bool is_tls);

void http1_response_send_error(int sock_client, int code, bool is_tls);

int http1_response_plain(int sock_client, HTTP1Session *session);

int http1_response_ssl(halmos_conn_t *conn, HTTP1Session *session);

#endif