#ifndef HALMOS_HTTP1_MANAGER_H
#define HALMOS_HTTP1_MANAGER_H

#include <stdbool.h>
#include "halmos_http1_header.h" // Pastikan RequestHeader terdefinisi

int http1_manager_session(int sock_client, bool is_tls);

// Tambahkan ini biar Response bisa manggil Manager balik
void http1_manager_ssl_response(int sock_client, RequestHeader *req);
#endif