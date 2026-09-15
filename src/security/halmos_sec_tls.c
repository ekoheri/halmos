#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
 
#include "halmos_sec_tls.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_connection.h"
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
 
// === PERBAIKAN: fd_to_ssl_map[] & g_ssl_map_lock GLOBAL DIHAPUS ===
//
// Sebelumnya modul ini punya struktur data & lock SENDIRI untuk memetakan
// fd -> SSL*, terpisah dari halmos_conn_t (yang sudah punya field `ssl`
// dan `io_lock` PER-KONEKSI di halmos_core_connection.c).
//
// Akibatnya: setiap ssl_send()/ssl_get_for_fd()/dst mengunci SATU mutex
// global yang sama untuk SEMUA koneksi sekaligus -> di beban concurrency
// tinggi, ratusan worker thread saling antre di lock yang sama walau
// mereka sebenarnya mengakses fd yang berbeda-beda (harusnya independen).
//
// Sekarang modul ini murni membaca/menulis conn->ssl langsung, TANPA
// mengambil lock apa pun di sini.
//
// PENTING - KONTRAK LOCKING:
// Fungsi-fungsi di bawah ini TIDAK melakukan locking sendiri karena
// SEMUA titik pemanggilan yang sudah ada (core_thread_pool_worker() saat
// dispatch, event_loop_cleanup_connection() saat cleanup) SUDAH memegang
// conn->io_lock (lewat core_conn_lock()) sepanjang durasi operasi SSL.
// Kalau fungsi ini ikut memanggil core_conn_lock() lagi di dalamnya,
// thread yang sama akan mengunci mutex non-recursive yang SAMA dua kali
// -> SELF-DEADLOCK.
//
// Karena itu: SETIAP pemanggil baru terhadap fungsi-fungsi ini (misalnya
// kode handshake TLS di http_bridge) WAJIB memastikan sudah memanggil
// core_conn_lock(conn) sebelumnya. Kalau ragu, panggil core_conn_lock()
// eksplisit di titik pemanggilan sebelum menyentuh SSL.
 
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    if (SSL_select_next_proto((unsigned char **)out, outlen, (const unsigned char *)arg, 12, in, inlen) 
        != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
 
int ssl_init(void) {
    if (!config.tls_enabled) return 0;
 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
 
    const SSL_METHOD *method = TLS_server_method();
    halmos_tls_ctx = SSL_CTX_new(method);
 
    if (!halmos_tls_ctx) {
        write_log_error("[SEC] Failed to create SSL context: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        return -1;
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
        return -1;
    }
 
    if (SSL_CTX_use_PrivateKey_file(halmos_tls_ctx, config.ssl_private_key_file, SSL_FILETYPE_PEM) <= 0) {
        write_log_error("[SEC] Failed to load private key file: %s", 
                        ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
 
    write_log("[SEC] TLS Engine: OpenSSL initialized with certificate.");
 
    return 0;
}
 
void ssl_cleanup(void) {
    if (halmos_tls_ctx == NULL) return; 
 
    // === PERBAIKAN: Tidak ada lagi fd_to_ssl_map[] untuk di-iterasi di sini. ===
    // Pembersihan conn->ssl per-koneksi yang masih tersisa saat shutdown
    // sekarang jadi tanggung jawab core_conn_destroy() di
    // halmos_core_connection.c, karena modul itu yang memiliki array
    // koneksi & lock granularnya. Modul TLS ini cukup membereskan
    // resource global miliknya sendiri (SSL_CTX).
 
    SSL_CTX_free(halmos_tls_ctx);
    halmos_tls_ctx = NULL;
 
    EVP_cleanup();
    ERR_free_strings();
    
    write_log("[SEC] TLS Engine: Resources cleaned up.");
}
 
// === PERBAIKAN: Deprecated - dipertahankan sebagai no-op agar tidak ===
// mematahkan pemanggil lama yang mungkin masih memanggil fungsi ini di
// urutan init. Tabel mapping global sudah tidak dipakai; kapasitas FD
// kini murni mengikuti array koneksi di halmos_core_connection.c.
void ssl_init_mapping(int max_fds) {
    (void)max_fds;
    write_log("[SEC] ssl_init_mapping() is deprecated (no-op): SSL pointers now live in conn->ssl.");
}
 
// PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock).
void ssl_set_for_fd(int fd, SSL *ssl) {
    halmos_conn_t *conn = core_conn_get(fd);
    if (!conn) {
        write_log_error("[SEC] Mapping failed: FD %d has no connection slot", fd);
        return;
    }
    conn->ssl = ssl;
}
 
// PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock).
SSL* ssl_get_for_fd(int fd) {
    halmos_conn_t *conn = core_conn_get(fd);
    if (!conn) return NULL;
    return conn->ssl;
}
 
// PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock).
void ssl_nullify_ptr(int fd) {
    halmos_conn_t *conn = core_conn_get(fd);
    if (!conn) return;
    conn->ssl = NULL;
}
 
/**
 * Pembebasan SSL objek. 
 * PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock),
 * sama seperti pola yang sudah dipakai event_loop_cleanup_connection().
 * Fungsi ini TIDAK mengunci apa pun sendiri untuk menghindari self-deadlock.
 */
void ssl_free_for_fd(int fd) {
    halmos_conn_t *conn = core_conn_get(fd);
    if (!conn) return;
 
    SSL *ssl_to_free = conn->ssl;
    conn->ssl = NULL; // Null-kan dulu agar pemanggil lain (di bawah lock yang sama) langsung lihat NULL
 
    if (ssl_to_free) {
        SSL_shutdown(ssl_to_free);
        SSL_free(ssl_to_free);
    }
}
 
// ssl_send() dipanggil dari dalam http_bridge_dispatch(), yang di
// core_thread_pool_worker() sudah dijalankan di bawah core_conn_lock(conn).
// Jadi ssl_get_for_fd() di sini aman diakses tanpa lock tambahan.
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
 
