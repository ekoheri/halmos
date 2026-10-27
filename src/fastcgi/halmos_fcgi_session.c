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

static FcgiSessionRegistry fcgi_registry = { .lock = PTHREAD_MUTEX_INITIALIZER };

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

    // --- DAFTARKAN KE REGISTRY ---
    fcgi_registry_add(session);

    session->sock_client = sock_client;
    
    // --- AMBIL GENERASI DARI CONNECTION TABLE ---
    halmos_conn_t *conn = core_conn_t_get(sock_client);
    if (conn) {
        session->client_generation = conn->generation;
    } else {
        session->client_generation = 0; 
    }

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

    fprintf(stderr, "[FCGI_SESSION_DEBUG] SUCCESS: Created FCGI session=%p with fpm_fd=%d\n", (void*)session, fpm_sock);
    return session;
}

/**
 * Membersihkan dan menghancurkan sesi FastCGI, serta menutup file descriptor terkait.
 */
void fcgi_session_destroy(FCGI_Session *session) {
    fprintf(stderr, "[DEBUG TRACE DESTROY] ENTER fcgi_session_destroy for session=%p\n", (void*)session);
    if (!session) return;

    pthread_mutex_lock(&session->lock);

    // GUARD MUTLAK: Jika fpm_fd sudah ditandai -99 (double destroy prevention)
    if (session->fpm_fd == -99) {
        fprintf(stderr, "[DEBUG TRACE DESTROY] WARNING: session=%p already marked destroyed (-99)! Aborting double-free.\n", (void*)session);
        pthread_mutex_unlock(&session->lock);
        return;
    }

    int target_fd = session->fpm_fd;
    session->fpm_fd = -99; // Tandai langsung di dalam lock

    // Simpan data penting sebelum mutex dihancurkan
    // (jika ada pointer lain yang perlu diamankan)

    pthread_mutex_unlock(&session->lock);

    // --- 1. CABUT DARI EPOLL POLLER ---
    if (target_fd >= 0) {
        fcgi_event_loop_del(target_fd);
    }

    // --- 2. LEPASKAN KEMBALI KE UPSTREAM POOL ---
    if (target_fd >= 0) {
        fcgi_upstream_release(target_fd);
    }

    // --- 3. PASTIKAN TIDAK ADA WORKER LAIN YANG MASIH MEMEGANG POINTER INI ---
    // Berikan jeda atau pastikan task worker sudah benar-benar selesai menggunakan session ini
    // sebelum memanggil pthread_mutex_destroy dan free(session).
    
    // --- CABUT DARI REGISTRY SEBELUM DI-FREE ---
    fcgi_registry_remove(session);

    pthread_mutex_destroy(&session->lock);
    fprintf(stderr, "[DEBUG TRACE DESTROY] FREED memory for session=%p\n", (void*)session);
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

// Daftarkan sesi baru
void fcgi_registry_add(void *session) {
    if (!session) return;
    pthread_mutex_lock(&fcgi_registry.lock);
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (fcgi_registry.sessions[i] == NULL) {
            fcgi_registry.sessions[i] = session;
            break;
        }
    }
    pthread_mutex_unlock(&fcgi_registry.lock);
}

// Hapus sesi dari registry saat akan di-free
void fcgi_registry_remove(void *session) {
    if (!session) return;
    pthread_mutex_lock(&fcgi_registry.lock);
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (fcgi_registry.sessions[i] == session) {
            fcgi_registry.sessions[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&fcgi_registry.lock);
}

// Cek apakah sesi benar-benar masih hidup dan terdaftar
bool fcgi_registry_is_valid(void *session) {
    if (!session) return false;
    bool valid = false;
    pthread_mutex_lock(&fcgi_registry.lock);
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (fcgi_registry.sessions[i] == session) {
            valid = true;
            break;
        }
    }
    pthread_mutex_unlock(&fcgi_registry.lock);
    return valid;
}