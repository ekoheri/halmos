#include "halmos_core_connection.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include <stdlib.h>
#include <string.h>

// Pointer dinamis menggantikan array statis g_connections[HALMOS_MAX_FD]
static halmos_conn_t *g_connections = NULL;

int core_conn_init(void) {
    if (g_max_fd == 0) {
        write_log_error("[ERR] Invalid g_max_fd (0) for connection system initialization");
        return -1;
    }

    // Alokasi memori dinamis berdasarkan g_max_fd dari core_adaptive_init()
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
    }

    write_log("[CORE] Connection system initialized with %u dynamic slots", g_max_fd);
    return 0;
}

void core_conn_destroy(void) {
    if (g_connections) {
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
    
    // Increment generation (FD lifetime identifier)
    uint32_t new_gen = atomic_fetch_add(&conn->generation, 1) + 1;
    
    atomic_store(&conn->state, CONN_STATE_READING);
    atomic_store(&conn->active, true);
    
    return new_gen;
}

void core_conn_deactivate(int fd) {
    if (fd < 0 || (uint32_t)fd >= g_max_fd || !g_connections) return;

    halmos_conn_t *conn = &g_connections[fd];
    
    // active = false adalah sinyal utama bahwa koneksi tidak boleh diproses lagi
    atomic_store(&conn->active, false);
    atomic_store(&conn->state, CONN_STATE_DEAD);
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