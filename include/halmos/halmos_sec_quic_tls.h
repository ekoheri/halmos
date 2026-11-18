#ifndef HALMOS_SEC_QUIC_TLS_H
#define HALMOS_SEC_QUIC_TLS_H

#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

extern SSL_CTX *halmos_quic_tls_ctx;

int quic_ssl_init(void);
void quic_ssl_cleanup(void);

void quic_ssl_set_for_conn(void *conn_ptr, SSL *ssl);
SSL* quic_ssl_get_for_conn(void *conn_ptr);
void quic_ssl_free_for_conn(void *conn_ptr);

#endif