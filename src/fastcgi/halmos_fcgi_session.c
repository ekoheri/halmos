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
#include <stdio.h>

// --- GLOBAL POOL STORAGE ---
static FCGI_Session *g_session_pool = NULL;
static int g_max_sessions = 0;
static pthread_mutex_t g_pool_lock;

/**
 * Menginisialisasi Global Session Pool sekali di awal server startup.
 */
bool fcgi_global_pool_init(int max_sessions) {
    g_max_sessions = (max_sessions > 0) ? max_sessions : MAX_FCGI_SESSIONS;
    
    // Alokasi memori tunggal untuk seluruh pool sesi
    g_session_pool = malloc(sizeof(FCGI_Session) * g_max_sessions);
    if (!g_session_pool) {
        write_log_error_code(ERR_FCGI_POOL_MEM, g_max_sessions);
        return false;
    }

    if (pthread_mutex_init(&g_pool_lock, NULL) != 0) {
        write_log_error_code(ERR_FCGI_POOL_MUTEX);
        free(g_session_pool);
        g_session_pool = NULL;
        return false;
    }

    // Inisialisasi setiap slot di dalam pool
    for (int i = 0; i < g_max_sessions; i++) {
        FCGI_Session *session = &g_session_pool[i];
        memset(session, 0, sizeof(FCGI_Session));
        session->session_id = i;
        session->sock_client = -1;
        session->fpm_fd = -1;
        session->state = FCGI_SESSION_FREE;
        atomic_init(&session->ref_count, 0);
        fcgi_ring_clear(&session->rx_buffer);
        fcgi_ring_clear(&session->tx_buffer);
        pthread_mutex_init(&session->lock, NULL);
    }

    return true;
}

/**
 * Menghancurkan Global Session Pool saat server dimatikan (shutdown).
 */
void fcgi_global_pool_destroy(void) {
    if (!g_session_pool) return;

    pthread_mutex_lock(&g_pool_lock);
    for (int i = 0; i < g_max_sessions; i++) {
        pthread_mutex_destroy(&g_session_pool[i].lock);
    }
    pthread_mutex_unlock(&g_pool_lock);

    pthread_mutex_destroy(&g_pool_lock);
    free(g_session_pool);
    g_session_pool = NULL;
}

FCGI_Session* fcgi_session_slot_get(int session_id) {
    if (session_id < 0 || session_id >= g_max_sessions) return NULL;
    return &g_session_pool[session_id];
}

/**
 * Membuat/Meminjam sesi FastCGI baru dari Global Pool (Tanpa malloc dinamis).
 */
FCGI_Session* fcgi_session_create(int sock_client, bool is_tls, SSL *ssl_conn, RequestHeader *req, int backend_type) {
    pthread_mutex_lock(&g_pool_lock);
    
    // Cari slot kosong di dalam Global Pool
    FCGI_Session *session = NULL;
    for (int i = 0; i < g_max_sessions; i++) {
        if (g_session_pool[i].state == FCGI_SESSION_FREE) {
            session = &g_session_pool[i];
            break;
        }
    }

    if (!session) {
        pthread_mutex_unlock(&g_pool_lock);
        write_log_warn_code(WARN_FCGI_POOL_EXHAUSTED, g_max_sessions, sock_client);
        return NULL; // Pool penuh / Max konkurensi tercapai
    }

    // Tandai slot sebagai aktif dan kunci secara eksklusif untuk inisialisasi
    pthread_mutex_lock(&session->lock);
    session->state = FCGI_STATE_INIT;
    pthread_mutex_unlock(&session->lock);
    
    pthread_mutex_unlock(&g_pool_lock);

    // --- INISIALISASI PROPERTI SESI ---
    session->sock_client = sock_client;
    session->is_tls = is_tls;
    session->ssl_conn = ssl_conn;
    session->is_http2 = false;
    session->http2_stream_id = 0;
    session->h2_session = NULL;
    session->h2_stream = NULL;

    // Set awal ref_count = 1 (dipegang oleh pembuat / HTTP1 Manager)
    atomic_store(&session->ref_count, 1);

    session->is_fcgi_active = false;
    session->fcgi_header_parsed = false;
    memset(session->fcgi_header_buf, 0, sizeof(session->fcgi_header_buf));
    session->fcgi_h_ptr = 0;

    // Bersihkan ring buffer statis
    fcgi_ring_clear(&session->rx_buffer);
    fcgi_ring_clear(&session->tx_buffer);

    session->header_pos = 0;
    session->header_sent = false;
    session->is_redirect = false;
    session->current_content_len = 0;
    session->current_padding_len = 0;
    session->bytes_processed_in_record = 0;
    session->last_activity = time(NULL);
    session->fpm_fd = -1;

    // --- 1. PILIH NODE & ACQUIRE KONEKSI UPSTREAM ---
    const char *target_ip = NULL;
    int target_port = 0;
    bool is_unix = false;

    if (fcgi_upstream_select_node(req, backend_type, &target_ip, &target_port, &is_unix) < 0) {
        // Kembalikan slot ke status FREE jika gagal
        write_log_error_code(ERR_FCGI_UPSTREAM_SEL, req ? req->uri : "UNKNOWN_URI");
        pthread_mutex_lock(&session->lock);
        session->state = FCGI_SESSION_FREE;
        pthread_mutex_unlock(&session->lock);
        return NULL; 
    }

    int fpm_sock = fcgi_upstream_acquire(is_unix ? target_ip : NULL, target_port);
    if (fpm_sock < 0) {
        // Kembalikan slot ke status FREE jika pool upstream habis       
        pthread_mutex_lock(&session->lock);
        session->state = FCGI_SESSION_FREE;
        pthread_mutex_unlock(&session->lock);
        return NULL; 
    }

    // --- 2. SET NON-BLOCKING ---
    int flags = fcntl(fpm_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fpm_sock, F_SETFL, flags | O_NONBLOCK);
    } else {
        write_log_error_code(ERR_FCGI_NONBLOCK, fpm_sock);
    }
    session->fpm_fd = fpm_sock;

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

/**
 * Menambah referensi secara atomik.
 */
FCGI_Session* fcgi_session_acquire(FCGI_Session *session) {
    if (!session) return NULL;
    atomic_fetch_add(&session->ref_count, 1);
    return session;
}

/**
 * Mengurangi referensi secara atomik. Jika 0, slot dikembalikan ke Global Pool (Tanpa free()).
 */
void fcgi_session_release(FCGI_Session *session) {
    if (!session) return;

    // Jika ref_count turun dari 1 ke 0, sesi ini sudah selesai dan bisa didaur ulang.
    if (atomic_fetch_sub(&session->ref_count, 1) == 1) {
        pthread_mutex_lock(&session->lock);

        // 1. Bersihkan fpm_fd dan kembalikan ke upstream pool
        int target_fd = session->fpm_fd;
        if (target_fd != -99 && target_fd != -1) {
            fcgi_event_loop_del(target_fd);
            fcgi_upstream_release(target_fd);
            session->fpm_fd = -99;
        }

        // 2. Reset status dan bersihkan ring buffer untuk pemakaian berikutnya
        session->sock_client = -1;
        session->is_tls = false;
        session->ssl_conn = NULL;
        session->is_http2 = false;
        session->http2_stream_id = 0;
        session->h2_session = NULL;
        session->h2_stream = NULL;
        
        fcgi_ring_clear(&session->rx_buffer);
        fcgi_ring_clear(&session->tx_buffer);

        session->state = FCGI_SESSION_FREE; // Kembalikan slot ke pool (READY TO REUSE)
        
        pthread_mutex_unlock(&session->lock);
    }
}

// --- IMPLEMENTASI RING BUFFER STATIS ---

size_t fcgi_ring_write(FCGIRingBuffer *rb, const char *src, size_t len) {
    if (!rb || !src || len == 0) return 0;

    size_t written = 0;
    while (written < len) {
        if (rb->size >= FCGI_RING_BUFFER_SIZE) {
            break; // Buffer penuh
        }
        
        // Indeks penulisan dihitung dari posisi tail
        size_t idx = rb->tail;
        rb->data[idx] = src[written++];
        rb->tail = (rb->tail + 1) % FCGI_RING_BUFFER_SIZE;
        rb->size++;
    }
    return written;
}

size_t fcgi_ring_read(FCGIRingBuffer *rb, char *dest, size_t max_len) {
    size_t read_bytes = 0;
    while (read_bytes < max_len && rb->size > 0) {
        dest[read_bytes++] = rb->data[rb->head];
        rb->head = (rb->head + 1) % FCGI_RING_BUFFER_SIZE;
        rb->size--;
    }
    return read_bytes;
}

void fcgi_ring_clear(FCGIRingBuffer *rb) {
    rb->head = 0;
    rb->tail = 0;
    rb->size = 0;
}