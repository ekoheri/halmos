#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_sec_tls.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Variable Global untuk SSL
SSL_CTX *halmos_tls_ctx = NULL;

// Variabel internal
static SSL** fd_to_ssl_map = NULL;
static int current_max_limit = 0;

// Mutex Guard untuk mengamankan konkurensi akses mapping antar Worker Threads
static pthread_mutex_t g_ssl_map_lock = PTHREAD_MUTEX_INITIALIZER;

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    if (SSL_select_next_proto((unsigned char **)out, outlen, (const unsigned char *)arg, 12, in, inlen) 
        != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

void ssl_init(void) {
    if (!config.tls_enabled) return;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    halmos_tls_ctx = SSL_CTX_new(method);

    if (!halmos_tls_ctx) {
        write_log_error("[SEC] Failed to create SSL context: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    static unsigned char protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };

    SSL_CTX_set_alpn_protos(halmos_tls_ctx, protos, sizeof(protos));
    SSL_CTX_set_alpn_select_cb(halmos_tls_ctx, alpn_select_cb, protos);

    if (SSL_CTX_use_certificate_chain_file(halmos_tls_ctx, config.ssl_certificate_file) <= 0) {
        write_log_error("[SEC] Failed to load certificate file: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(halmos_tls_ctx, config.ssl_private_key_file, SSL_FILETYPE_PEM) <= 0) {
        write_log_error("[SEC] Failed to load private key file: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    write_log("[SEC] TLS Engine: OpenSSL initialized with certificate.");
}

void ssl_cleanup(void) {
    if (halmos_tls_ctx == NULL) return; 

    pthread_mutex_lock(&g_ssl_map_lock);
    if (fd_to_ssl_map != NULL) {
        for (int i = 0; i < current_max_limit; i++) {
            if (fd_to_ssl_map[i] != NULL) {
                SSL_free(fd_to_ssl_map[i]);
                fd_to_ssl_map[i] = NULL;
            }
        }
        free(fd_to_ssl_map);
        fd_to_ssl_map = NULL;
    }
    pthread_mutex_unlock(&g_ssl_map_lock);

    SSL_CTX_free(halmos_tls_ctx);
    halmos_tls_ctx = NULL;

    EVP_cleanup();
    ERR_free_strings();
    
    write_log("[SEC] TLS Engine: Resources cleaned up.");
}

void ssl_init_mapping(int max_fds) {
    current_max_limit = max_fds;
    fd_to_ssl_map = calloc(current_max_limit, sizeof(SSL*));
    if (!fd_to_ssl_map) {
        write_log_error("[SEC] FATAL: Failed to allocate SSL mapping table for %d FDs: %s", 
                        max_fds, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void ssl_set_for_fd(int fd, SSL *ssl) {
    if (fd < 0 || fd >= current_max_limit) {
        write_log_error("[SEC] Mapping failed: FD %d is out of range (Limit: %d)", 
                        fd, current_max_limit);
        return;
    }

    pthread_mutex_lock(&g_ssl_map_lock);
    if (fd_to_ssl_map) {
        fd_to_ssl_map[fd] = ssl;
    }
    pthread_mutex_unlock(&g_ssl_map_lock);
}

SSL* ssl_get_for_fd(int fd) {
    if (fd < 0 || fd >= current_max_limit) return NULL;

    pthread_mutex_lock(&g_ssl_map_lock);
    SSL *ssl = (fd_to_ssl_map) ? fd_to_ssl_map[fd] : NULL;
    pthread_mutex_unlock(&g_ssl_map_lock);

    return ssl;
}

void ssl_nullify_ptr(int fd) {
    if (fd < 0 || fd >= current_max_limit) return;

    pthread_mutex_lock(&g_ssl_map_lock);
    if (fd_to_ssl_map) {
        fd_to_ssl_map[fd] = NULL;
    }
    pthread_mutex_unlock(&g_ssl_map_lock);
}

/**
 * Pembebasan SSL objek secara atomic untuk mencegah Double Free / Race Condition.
 */
void ssl_free_for_fd(int fd) {
    if (fd < 0 || fd >= current_max_limit) return;

    SSL *ssl_to_free = NULL;

    pthread_mutex_lock(&g_ssl_map_lock);
    if (fd_to_ssl_map && fd_to_ssl_map[fd]) {
        ssl_to_free = fd_to_ssl_map[fd];
        fd_to_ssl_map[fd] = NULL; // Langsung NULL-kan agar thread lain mendeteksi NULL
    }
    pthread_mutex_unlock(&g_ssl_map_lock);

    if (ssl_to_free) {
        SSL_shutdown(ssl_to_free);
        SSL_free(ssl_to_free);
    }
}

ssize_t ssl_send(int fd, const void *buf, size_t len) {
    SSL *ssl = ssl_get_for_fd(fd);
    if (!ssl) return -1;

    int ret = SSL_write(ssl, buf, (int)len);
    
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            return 0; 
        }
        return -1;
    }

    return ret;
}