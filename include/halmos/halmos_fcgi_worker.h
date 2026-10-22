#ifndef HALMOS_FCGI_WORKER_H
#define HALMOS_FCGI_WORKER_H

#include <stdbool.h>
#include <pthread.h>

// --- 1. STRUKTUR WORKER POOL (Adaptive) ---
typedef struct {
    int min_workers;            // Batas minimal worker (dihitung dari core)
    int max_workers;            // Batas maksimal worker
    volatile bool running;      // Status kontrol pool
} FCGIWorkerPool;

bool halmos_fcgi_worker_pool_init(void);

void halmos_fcgi_worker_pool_stop(void);

void* halmos_fcgi_worker_routine(void *arg);

bool halmos_fcgi_is_running(void);

// Helper untuk spawn detached worker
int halmos_fcgi_spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg);

#endif // HALMOS_FCGI_WORKER_H