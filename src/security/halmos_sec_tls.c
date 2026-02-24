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

#include <sys/socket.h>  // Biar kenal shutdown(), recv(), SHUT_WR, MSG_DONTWAIT
#include <netinet/in.h>  // Tambahan buat struct networking
#include <arpa/inet.h>   // Buat konversi alamat IP kalau butuh

// Variable Global untuk SSl
SSL_CTX *halmos_tls_ctx = NULL;

// Variabel ini "sembunyi" di dalam file ini saja
static SSL** fd_to_ssl_map = NULL;
static int current_max_limit = 0;


// Fungsi untuk mengaktifkan SSL

void ssl_init() {
    if (!config.tls_enabled) return; // Jangan inisialisasi kalau di config OFF

    // 1. Inisialisasi library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 2. Buat Context (Gunakan metode TLS_server_method agar support TLS 1.2 & 1.3)
    const SSL_METHOD *method = TLS_server_method();
    halmos_tls_ctx = SSL_CTX_new(method);

    if (!halmos_tls_ctx) {
        write_log_error("[SEC] Failed to create SSL context: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // 3. Load Certificate & Private Key (Nama file bisa diambil dari config)
    if (SSL_CTX_use_certificate_file(halmos_tls_ctx, config.ssl_certificate_file, SSL_FILETYPE_PEM) <= 0) {
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

void ssl_cleanup() {
    // Jika context NULL, berarti TLS memang tidak aktif atau sudah di-cleanup
    if (halmos_tls_ctx == NULL) {
        return; 
    }

    // --- FD harus dibersihkan ---
    if (fd_to_ssl_map != NULL) {
        // Bebaskan semua objek SSL yang mungkin masih tersisa di map
        for (int i = 0; i < current_max_limit; i++) {
            if (fd_to_ssl_map[i] != NULL) {
                SSL_free(fd_to_ssl_map[i]);
            }
        }
        free(fd_to_ssl_map);
        fd_to_ssl_map = NULL;
    }
    // ---------------------
    SSL_CTX_free(halmos_tls_ctx);
    halmos_tls_ctx = NULL;

    // Bersihkan sisa-sisa library OpenSSL dari memori
    EVP_cleanup();
    ERR_free_strings();
    
    write_log("[SEC] TLS Engine: Resources cleaned up.");
}

/**
 * Mendapatkan atau membuat objek SSL untuk FD tertentu
 */
void ssl_init_mapping(int max_fds) {
    current_max_limit = max_fds;
    // Gunakan calloc agar semua otomatis jadi NULL
    fd_to_ssl_map = calloc(current_max_limit, sizeof(SSL*));
    if (!fd_to_ssl_map) {
        write_log_error("[SEC] FATAL: Failed to allocate SSL mapping table for %d FDs: %s", 
                        max_fds, strerror(errno));
        exit(EXIT_FAILURE); // Jika ini gagal, server tidak bisa jalan
    }
}

void ssl_set_for_fd(int fd, SSL *ssl) {
    if (fd_to_ssl_map && fd >= 0 && fd < current_max_limit) {
        fd_to_ssl_map[fd] = ssl;
    } else {
        write_log_error("[SEC] Mapping failed: FD %d is out of range (Limit: %d)", 
                        fd, current_max_limit);
    }
}

SSL* ssl_get_for_fd(int fd) {
    if (fd_to_ssl_map && fd >= 0 && fd < current_max_limit) {
        return fd_to_ssl_map[fd];
    }
    return NULL;
}

void ssl_nullify_ptr(int fd) {
    if (fd_to_ssl_map && fd >= 0 && fd < current_max_limit) {
        fd_to_ssl_map[fd] = NULL;
    }
}

/**
 * ssl_send
 * Fungsi Jembatan: Response.c manggil ini buat kirim data HTTPS.
 * JANGAN dikasih 'static' supaya bisa dipanggil dari luar file Manager!
 */
ssize_t ssl_send(int fd, const void *buf, size_t len) {
    SSL *ssl = ssl_get_for_fd(fd);
    if (!ssl) {
        //fprintf(stderr, "[SSL ERROR] Tidak nemu objek SSL untuk FD: %d\n", fd);
        return -1;
    }

    int ret = SSL_write(ssl, buf, (int)len);
    
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        
        // Cek apakah ini cuma error "tunggu sebentar" (Non-blocking I/O)
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Return 0 artinya: Gak ada data terkirim sekarang, tapi koneksi masih SEHAT.
            // Panggil lagi nanti ya!
            return 0; 
        }

        // Kalau kodenya bukan WANT_WRITE/READ, baru ini error beneran (koneksi putus, dll)
        //fprintf(stderr, "[SSL ERROR] SSL_write GAGAL FATAL, code: %d\n", err);
        return -1;
    }

    return ret;
}
