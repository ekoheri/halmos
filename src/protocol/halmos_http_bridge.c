#include "halmos_http_bridge.h"
#include "halmos_global.h"
#include "halmos_http1_manager.h"
#include "halmos_security.h"

#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/**
 * Logika "Mengintip" Protokol
 */


halmos_protocol_t bridge_detect(int sock_client) {
    char buffer[32]; 
    memset(buffer, 0, sizeof(buffer)); 
    ssize_t n;

    if (config.tls_enabled) {
        SSL *ssl = get_ssl_for_fd(sock_client);
        if (!ssl) {
            return PROTOCOL_ERROR;
        }

        n = SSL_peek(ssl, buffer, sizeof(buffer) - 1);
        
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return PROTOCOL_RETRY;
            return PROTOCOL_ERROR;
        }
    } else {
        n = recv(sock_client, buffer, sizeof(buffer) - 1, MSG_PEEK | MSG_DONTWAIT);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return PROTOCOL_RETRY;
            return PROTOCOL_ERROR;
        }
    }

    if (n < 8) {
        return PROTOCOL_RETRY;
    }

    if (strstr(buffer, "HTTP/1.")) {
        return PROTOCOL_HTTP1;
    }

    if (strncmp(buffer, "PRI * HTTP/2", 12) == 0) {
        return PROTOCOL_HTTP2;
    }

    return PROTOCOL_UNKNOWN;
}

/**
 * Logika Pengalihan Aliran (Multiplexer)
 */

int bridge_dispatch(int sock_client) {
    // JANGAN PEEK kalau TLS aktif! 
    // OpenSSL itu sensitif, kalau diintip doang sisa datanya sering nyangkut.
    if (config.tls_enabled) {
        return handle_http1_session(sock_client); 
    }

    // Kalau HTTP biasa, silakan intip sesukamu
    halmos_protocol_t proto = bridge_detect(sock_client);

    if (proto == PROTOCOL_RETRY) return 1;

    if (proto == PROTOCOL_HTTP1) {
        return handle_http1_session(sock_client);
    }

    return 0; // Unknown or unsupported
}

int bridge_dispatch_lama(int sock_client) {
    halmos_protocol_t proto = bridge_detect(sock_client);

    if (proto == PROTOCOL_RETRY) {
        return 1;
    }

    int result = 0;

    switch (proto) {
        case PROTOCOL_HTTP1:
            result = handle_http1_session(sock_client);
            break;

        case PROTOCOL_HTTP2:
            result = 0;
            break;

        default:
            result = 0; 
            break;
    }
    return result;
}