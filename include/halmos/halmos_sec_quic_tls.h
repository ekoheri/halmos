#ifndef HALMOS_SEC_QUIC_TLS_H
#define HALMOS_SEC_QUIC_TLS_H

#include "halmos_core_quic_conn_table.h"

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
void sec_quic_tls_feed_ssl_and_respond(SSL *ssl, QuicConnection *conn, int sock_server, 
                                       const unsigned char *feed_buffer, size_t feed_len,
                                       const unsigned char *client_dcid, size_t client_dcid_len,
                                       const unsigned char *client_scid, size_t client_scid_len,
                                       int is_retransmit);

#endif