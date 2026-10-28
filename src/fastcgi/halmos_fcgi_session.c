#include "halmos_fcgi_session.h"
#include "halmos_fcgi_upstream.h"
#include "halmos_fcgi_event_loop.h"
#include "halmos_core_conn_table.h"
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
    fprintf(stderr, "[FCGI_SESSION_DEBUG] ENTER fcgi_session_create for client_sock=%d, backend_type=%d\n", sock_client, backend_type);

    FCGI_Session *session = (FCGI_Session*)malloc(sizeof(FCGI_Session));
    if (!session) {
        fprintf(stderr, "[FCGI_SESSION_DEBUG] ERROR: Failed to allocate memory for FCGI_Session\n");
        return NULL;
    }

    memset(session, 0, sizeof(FCGI_Session));

    // --- INISIALISASI MUTEX DI AWAL AGAR AMAN SAAT CLEANUP ---
    if (pthread_mutex_init(&session->lock, NULL) != 0) {
        fprintf(stderr, "[FCGI_SESSION_DEBUG] ERROR: Failed to initialize session mutex\n");
        free(session);
        return NULL;
    }

    // --- ATOMIC REFERENCE COUNTING ---
    // Set awal ref_count = 1 (dipegang oleh pembuat / HTTP1 Manager)
    atomic_init(&session->ref_count, 1);

    // CATATAN: fcgi_registry_add(session) DIHAPUS karena sudah digantikan ref_count!

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
    session->fpm_fd = -1; 

    // --- 1. PILIH NODE & ACQUIRE KONEKSI ---
    const char *target_ip = NULL;
    int target_port = 0;
    bool is_unix = false;

    if (fcgi_upstream_select_node(req, backend_type, &target_ip, &target_port, &is_unix) < 0) {
        fprintf(stderr, "[FCGI_SESSION_DEBUG] ERROR: fcgi_upstream_select_node failed\n");
        pthread_mutex_destroy(&session->lock);
        free(session);
        return NULL; 
    }

    int fpm_sock = fcgi_upstream_acquire(is_unix ? target_ip : NULL, target_port);
    if (fpm_sock < 0) {
        fprintf(stderr, "[UPSTREAM_FATAL] fcgi_upstream_acquire FAILED! Target IP: %s, Port: %d (Pool Exhausted!)\n", target_ip ? target_ip : "NULL", target_port);
        pthread_mutex_destroy(&session->lock);
        free(session);
        return NULL; // Gagal acquire dari pool -> Memicu ERR_PROTO_H1_FSM (502)
    }

    // --- 2. SET NON-BLOCKING ---
    int flags = fcntl(fpm_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fpm_sock, F_SETFL, flags | O_NONBLOCK);
    }
    session->fpm_fd = fpm_sock;

    fprintf(stderr, "[FCGI_SESSION_DEBUG] SUCCESS: Created FCGI session=%p with fpm_fd=%d, ref_count=1\n", (void*)session, fpm_sock);
    return session;
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

// Menambah referensi secara atomik
FCGI_Session* fcgi_session_acquire(FCGI_Session *session) {
    if (!session) return NULL;
    atomic_fetch_add(&session->ref_count, 1);
    return session;
}

// Mengurangi referensi secara atomik. Jika 0, memori dibebaskan secara aman.
void fcgi_session_release(FCGI_Session *session) {
    if (!session) return;

    // Jika ref_count turun dari 1 ke 0, tidak ada lagi yang memegang sesi ini.
    if (atomic_fetch_sub(&session->ref_count, 1) == 1) {
        fprintf(stderr, "[DEBUG TRACE RELEASE] Ref count zero, freeing session=%p\n", (void*)session);

        // 1. Bersihkan fpm_fd dan kembalikan ke upstream pool
        pthread_mutex_lock(&session->lock);
        int target_fd = session->fpm_fd;
        if (target_fd != -99 && target_fd != -1) {
            fcgi_event_loop_del(target_fd);
            fcgi_upstream_release(target_fd);
            session->fpm_fd = -99;
        }
        pthread_mutex_unlock(&session->lock);

        // 2. Hancurkan mutex
        pthread_mutex_destroy(&session->lock);

        // 3. Bebaskan memori
        free(session);
    }
}
