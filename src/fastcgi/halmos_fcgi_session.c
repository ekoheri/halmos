#include "halmos_fcgi_session.h"
#include "halmos_log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/**
 * Membuat dan menginisialisasi sesi FastCGI baru untuk sebuah request klien.
 */
HalmosFCGISession* halmos_fcgi_session_create(int sock_client, bool is_tls, SSL *ssl_conn) {
    HalmosFCGISession *session = (HalmosFCGISession*)malloc(sizeof(HalmosFCGISession));
    if (!session) {
        return NULL;
    }

    memset(session, 0, sizeof(HalmosFCGISession));

    session->sock_client = sock_client;
    session->fpm_fd = -1; // Belum terhubung ke PHP-FPM
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
void halmos_fcgi_session_destroy(HalmosFCGISession *session) {
    if (!session) return;

    pthread_mutex_lock(&session->lock);

    // Tutup socket PHP-FPM jika masih terbuka
    if (session->fpm_fd != -1) {
        close(session->fpm_fd);
        session->fpm_fd = -1;
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
void halmos_fcgi_session_set_state(HalmosFCGISession *session, FCGI_AsyncState new_state) {
    if (!session) return;

    pthread_mutex_lock(&session->lock);
    session->state = new_state;
    session->last_activity = time(NULL);
    pthread_mutex_unlock(&session->lock);
}