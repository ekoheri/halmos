#include "halmos_core_connection.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include <stdlib.h>
#include <string.h>

static halmos_conn_t *g_connections = NULL;

int core_conn_init(void) {
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

        // Inisialisasi Mutex Per Slot FD
        if (pthread_mutex_init(&g_connections[i].io_lock, NULL) != 0) {
            write_log_error("[ERR] Failed to init io_lock for FD slot %u", i);
            return -1;
        }
    }

    write_log("[CORE] Connection system initialized with %u dynamic slots + io_locks", g_max_fd);
    return 0;
}

void core_conn_destroy(void) {
    if (g_connections) {
        for (uint32_t i = 0; i < g_max_fd; i++) {
            pthread_mutex_destroy(&g_connections[i].io_lock);
        }
        free(g_connections);
        g_connections = NULL;
    }
    write_log("[CORE] Connection system destroyed");
}

halmos_conn_t* core_conn_get(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return NULL;
    return &g_connections[fd];
}

uint32_t core_conn_activate(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return 0;

    halmos_conn_t *conn = &g_connections[fd];
    
    // Kunci slot sebentar saat aktivasi untuk reset pointer SSL & state
    pthread_mutex_lock(&conn->io_lock);

    uint32_t new_gen = atomic_fetch_add(&conn->generation, 1) + 1;
    conn->ssl = NULL;
    
    atomic_store(&conn->state, CONN_STATE_READING);
    atomic_store(&conn->active, true);

    pthread_mutex_unlock(&conn->io_lock);
    
    return new_gen;
}

void core_conn_deactivate(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return;

    halmos_conn_t *conn = &g_connections[fd];
    
    // Matikan flag active terlebih dahulu (atomic signal untuk fast path)
    atomic_store(&conn->active, false);
    atomic_store(&conn->state, CONN_STATE_DEAD);

    // Kunci slot untuk mengosongkan resource terikat (seperti pointer SSL)
    pthread_mutex_lock(&conn->io_lock);
    conn->ssl = NULL;
    pthread_mutex_unlock(&conn->io_lock);
}

bool core_conn_is_valid(int fd, uint32_t expected_generation) {
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

void core_conn_lock(halmos_conn_t *conn) {
    if (conn) pthread_mutex_lock(&conn->io_lock);
}

void core_conn_unlock(halmos_conn_t *conn) {
    if (conn) pthread_mutex_unlock(&conn->io_lock);
}