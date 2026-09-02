#ifndef HALMOS_CORE_CONNECTION_H
#define HALMOS_CORE_CONNECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

// Forward declaration untuk SSL agar tidak wajib include header openssl di sini jika tidak diperlukan
typedef struct ssl_st SSL;

typedef enum {
    CONN_STATE_READING = 0,
    CONN_STATE_PROCESSING,
    CONN_STATE_WRITING,
    CONN_STATE_CLOSING,
    CONN_STATE_DEAD
} halmos_conn_state_t;

typedef struct {
    int fd;
    
    /**
     * Identifies a particular lifetime of an FD.
     * Incremented every time the FD is assigned to a new connection.
     * Worker events must carry this value to detect stale FD reuse.
     */
    _Atomic uint32_t generation;
    
    _Atomic bool active;
    _Atomic halmos_conn_state_t state;

    /* --- TAMBAHAN KRITIS UNTUK SYNC & I/O ISOLATION --- */
    pthread_mutex_t io_lock;  /**< Mengunci seluruh operasi I/O (SSL_read/write, HTTP/2 frame, close) */
    SSL *ssl;                 /**< Pointer SSL/TLS context per koneksi */
} halmos_conn_t;

/**
 * FD lifetime payload yang dilempar oleh Event Loop ke Worker Queue
 */
typedef struct {
    int fd;
    uint32_t generation;
} halmos_event_t;

// API Core Connection Metadata (Dinamis berdasarkan g_max_fd)
int core_conn_init(void);
void core_conn_destroy(void);

halmos_conn_t* core_conn_get(int fd);
uint32_t core_conn_activate(int fd);
void core_conn_deactivate(int fd);
bool core_conn_is_valid(int fd, uint32_t expected_generation);

// Helpmate Lock Operations
void core_conn_lock(halmos_conn_t *conn);
void core_conn_unlock(halmos_conn_t *conn);

#endif // HALMOS_CORE_CONNECTION_H