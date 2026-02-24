#ifndef HALMOS_SEC_TLS_H
#define HALMOS_SEC_TLS_H

#include <stdbool.h>
#include <sys/types.h>

// tambahan untuk library SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

// Global context (hanya deklarasi)
extern SSL_CTX *halmos_tls_ctx;

/*
* Fungsi-fungsi untuk mengaktifkan SSL
*/
void ssl_init();
void ssl_cleanup();
void ssl_init_mapping(int max_fds);
void ssl_set_for_fd(int fd, SSL *ssl);
SSL* ssl_get_for_fd(int fd);
void ssl_nullify_ptr(int fd);

// Fungsi Operasional
ssize_t ssl_send(int fd, const void *buf, size_t len);

#endif