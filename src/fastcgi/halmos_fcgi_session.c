#include "halmos_fcgi_session.h"
#include "halmos_fcgi_upstream.h"
#include "halmos_http1_header.h"

#include "halmos_log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Membuat dan menginisialisasi sesi FastCGI baru untuk sebuah request klien.
 */
FCGI_Session* fcgi_session_create(int sock_client, bool is_tls, SSL *ssl_conn, RequestHeader *req, int backend_type) {
    FCGI_Session *session = (FCGI_Session*)malloc(sizeof(FCGI_Session));
    if (!session) {
        return NULL;
    }

    memset(session, 0, sizeof(FCGI_Session));

    session->sock_client = sock_client;
    session->is_tls = is_tls;
    session->ssl_conn = ssl_conn;
    session->state = FCGI_STATE_INIT;

    // Inisialisasi buffer & posisi
    session->header_pos = 0;
    session->header_sent = false;
    session->is_redirect = false;
    session->current_content_len = 0;
    session->current_padding_len = 0;
    session->bytes_processed_in_record = 0;
    session->last_activity = time(NULL);

    session->fpm_fd = -1; // Belum terhubung ke PHP-FPM
    // --- 1. PILIH NODE & ACQUIRE KONEKSI DITANGANI DISINI ---
    const char *target_ip = NULL;
    int target_port = 0;
    bool is_unix = false;

    if (fcgi_upstream_select_node(req, backend_type, &target_ip, &target_port, &is_unix) < 0) {
        pthread_mutex_destroy(&session->lock);
        free(session);
        return NULL; // Gagal pilih node
    }

    int fpm_sock = fcgi_upstream_acquire(is_unix ? target_ip : NULL, target_port);
    if (fpm_sock < 0) {
        pthread_mutex_destroy(&session->lock);
        free(session);
        return NULL; // Gagal acquire dari pool
    }

    // --- 2. SET NON-BLOCKING ---
    int flags = fcntl(fpm_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fpm_sock, F_SETFL, flags | O_NONBLOCK);
    }
    session->fpm_fd = fpm_sock;

    // Inisialisasi mutex lokal sesi untuk keamanan konkuren antar thread worker
    if (pthread_mutex_init(&session->lock, NULL) != 0) {
        free(session);
        return NULL;
    }

    return session;
}

/**
 * Membersihkan dan menghancurkan sesi FastCGI, serta menutup file descriptor terkait.
 */
void fcgi_session_destroy(FCGI_Session *session) {
    if (!session) return;

    pthread_mutex_lock(&session->lock);

    // Tutup socket PHP-FPM jika masih terbuka
    if (session->fpm_fd != -1) {
        fcgi_upstream_release(session->fpm_fd);
        session->fpm_fd = -1;
        //close(session->fpm_fd);
        //session->fpm_fd = -1;
    }

    // Catatan: sock_client dan ssl_conn dikelola oleh manajer HTTP frontend,
    // jadi jangan ditutup di sini kecuali lifecycle-nya memang dipindahkan ke FastCGI.

    pthread_mutex_unlock(&session->lock);
    pthread_mutex_destroy(&session->lock);

    free(session);
}

/**
 * Memperbarui status state FSM sesi dengan aman (thread-safe).
 */
void fcgi_session_set_state(FCGI_Session *session, FCGI_AsyncState new_state) {
    if (!session) return;

    pthread_mutex_lock(&session->lock);
    session->state = new_state;
    session->last_activity = time(NULL);
    pthread_mutex_unlock(&session->lock);
}