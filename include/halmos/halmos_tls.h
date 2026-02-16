#ifndef HALMOS_TLS_H
#define HALMOS_TLS_H

#include <stdbool.h>
#include <sys/types.h>

// tambahan untuk library SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

// Global context (hanya deklarasi)
extern SSL_CTX *halmos_tls_ctx;

// Fungsi Lifecycle
void init_openssl_runtime();
void cleanup_openssl();

/*
* Fungsi-fungsi untuk mengaktifkan SSL
*/
void init_openssl_runtime();
void cleanup_openssl();
void init_ssl_mapping(int max_fds);
void set_ssl_for_fd(int fd, SSL *ssl);
SSL* get_ssl_for_fd(int fd);
void nullify_ssl_ptr(int fd);

// Fungsi Operasional
void cleanup_connection_properly(int sock_client);
ssize_t halmos_send_ssl(int fd, const void *buf, size_t len);

#endif