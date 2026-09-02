#ifndef HALMOS_CORE_CONNECTION_H
#define HALMOS_CORE_CONNECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

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

#endif // HALMOS_CORE_CONNECTION_H