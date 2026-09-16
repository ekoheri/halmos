#include "halmos_core_conn_table.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
 
static halmos_conn_t *g_connections = NULL;

// Helper opsional untuk reset write buffer pada koneksi
void core_conn_t_clear_write_buf(halmos_conn_t *conn) {
    if (!conn) return;
    if (conn->write_buf) {
        free(conn->write_buf);
        conn->write_buf = NULL;
    }
    conn->write_len = 0;
    conn->write_offset = 0;
}

int core_conn_t_init(void) {
    if (g_max_fd == 0) {
        write_log_error("[ERR] Invalid g_max_fd (0) for connection system initialization");
        return -1;
    }
 
    g_connections = calloc(g_max_fd, sizeof(halmos_conn_t));
    if (!g_connections) {
        write_log_error("[ERR] Out of memory allocating %u connection slots", g_max_fd);
        return -1;
    }
 
    for (uint32_t i = 0; i < g_max_fd; i++) {
        g_connections[i].fd = (int)i;
        atomic_init(&g_connections[i].generation, 0);
        atomic_init(&g_connections[i].active, false);
        atomic_init(&g_connections[i].state, CONN_STATE_DEAD);
        g_connections[i].ssl = NULL;
        g_connections[i].protocol_session = NULL;
        g_connections[i].protocol_session_destroy = NULL;
 
        // Inisialisasi Mutex Per Slot FD
        if (pthread_mutex_init(&g_connections[i].io_lock, NULL) != 0) {
            write_log_error("[ERR] Failed to init io_lock for FD slot %u", i);
            return -1;
        }
    }
 
    write_log("[CORE] Connection system initialized with %u dynamic slots + io_locks", g_max_fd);
    return 0;
}
 
void core_conn_t_destroy(void) {
    if (g_connections) {
        // === PERBAIKAN: Bereskan sisa conn->ssl di sini. ===
        // Dulu ini tugas fd_to_ssl_map[] loop di halmos_sec_tls.c (sudah
        // dihapus karena jadi sumber lock kontensi global). Modul koneksi
        // ini yang memiliki array & siklus hidupnya, jadi tanggung jawab
        // pembersihan akhir dipindah ke sini. Ini teardown single-threaded
        // (dipanggil saat server benar-benar berhenti), jadi tidak perlu
        // io_lock per-slot lagi di titik ini.
        for (uint32_t i = 0; i < g_max_fd; i++) {
            if (g_connections[i].ssl) {
                SSL_shutdown(g_connections[i].ssl);
                SSL_free(g_connections[i].ssl);
                g_connections[i].ssl = NULL;
            }
            // === TAMBAHAN: bereskan sisa protocol_session (mis. HTTP2Session) ===
            // Dipanggil generik lewat function pointer, connection.c tidak
            // perlu tahu isi struct-nya.
            if (g_connections[i].protocol_session && g_connections[i].protocol_session_destroy) {
                g_connections[i].protocol_session_destroy(g_connections[i].protocol_session);
                g_connections[i].protocol_session = NULL;
                g_connections[i].protocol_session_destroy = NULL;
            }
        }
 
        for (uint32_t i = 0; i < g_max_fd; i++) {
            pthread_mutex_destroy(&g_connections[i].io_lock);
        }
        free(g_connections);
        g_connections = NULL;
    }
    write_log("[CORE] Connection system destroyed");
}
 
halmos_conn_t* core_conn_t_get(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return NULL;
    return &g_connections[fd];
}
 
uint32_t core_conn_t_activate(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return 0;
 
    halmos_conn_t *conn = &g_connections[fd];
    
    pthread_mutex_lock(&conn->io_lock);
 
    uint32_t new_gen = atomic_fetch_add(&conn->generation, 1) + 1;
    conn->ssl = NULL;

    /* Reset Write Buffer State */
    core_conn_t_clear_write_buf(conn);
    conn->epoll_events = 0;
 
    if (conn->protocol_session && conn->protocol_session_destroy) {
        conn->protocol_session_destroy(conn->protocol_session);
    }
    conn->protocol_session = NULL;
    conn->protocol_session_destroy = NULL;
    
    atomic_store(&conn->state, CONN_STATE_READING);
    atomic_store(&conn->active, true);
 
    pthread_mutex_unlock(&conn->io_lock);
    
    return new_gen;
}
 
void core_conn_t_deactivate(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return;
 
    halmos_conn_t *conn = &g_connections[fd];
    
    atomic_store(&conn->active, false);
    atomic_store(&conn->state, CONN_STATE_DEAD);
 
    pthread_mutex_lock(&conn->io_lock);
    conn->ssl = NULL;

    /* Bebaskan memory jika koneksi mati saat payload belum selesai terkirim */
    core_conn_t_clear_write_buf(conn);

    if (conn->protocol_session && conn->protocol_session_destroy) {
        conn->protocol_session_destroy(conn->protocol_session);
    }
    conn->protocol_session = NULL;
    conn->protocol_session_destroy = NULL;
    pthread_mutex_unlock(&conn->io_lock);
}
 
bool core_conn_t_is_valid(int fd, uint32_t expected_generation) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return false;
 
    halmos_conn_t *conn = &g_connections[fd];
 
    // Check 1: Apakah socket aktif?
    if (!atomic_load(&conn->active)) return false;
    
    // Check 2: Apakah lifetime FD masih sama? (Detect stale event)
    if (atomic_load(&conn->generation) != expected_generation) return false;
    
    // Check 3: Guard state pengecekan status closing/dead
    halmos_conn_state_t st = atomic_load(&conn->state);
    if (st == CONN_STATE_CLOSING || st == CONN_STATE_DEAD) return false;
 
    return true;
}
 
void core_conn_t_lock(halmos_conn_t *conn) {
    if (conn) pthread_mutex_lock(&conn->io_lock);
}
 
void core_conn_t_unlock(halmos_conn_t *conn) {
    if (conn) pthread_mutex_unlock(&conn->io_lock);
}
 
// PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock).
// Tidak ada locking internal di sini - lihat catatan di header.
void core_conn_t_set_protocol_session(halmos_conn_t *conn, void *session, void (*destroy_fn)(void *)) {
    if (!conn) return;
    conn->protocol_session = session;
    conn->protocol_session_destroy = destroy_fn;
}
 
// PRASYARAT: pemanggil harus sudah memegang conn->io_lock (core_conn_lock).
void core_conn_t_destroy_protocol_session(halmos_conn_t *conn) {
    if (!conn) return;
    if (conn->protocol_session && conn->protocol_session_destroy) {
        conn->protocol_session_destroy(conn->protocol_session);
    }
    conn->protocol_session = NULL;
    conn->protocol_session_destroy = NULL;
}
