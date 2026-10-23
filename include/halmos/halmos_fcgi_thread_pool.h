#ifndef HALMOS_FCGI_THREAD_POOL_H
#define HALMOS_FCGI_THREAD_POOL_H

#include <stdbool.h>
#include <pthread.h>

// --- 1. STRUKTUR WORKER POOL (Adaptive) ---
typedef struct {
    int min_workers;            // Batas minimal worker (dihitung dari core)
    int max_workers;            // Batas maksimal worker
    volatile bool running;      // Status kontrol pool
} FCGI_WorkerPool;

bool fcgi_thread_pool_start(void);

void fcgi_thread_pool_stop(void);

void* fcgi_thread_pool_worker(void *arg);

bool fcgi_thread_pool_is_running(void);

int fcgi_thread_pool_spawn_detached(pthread_t *out_tid, void *(*routine)(void *), void *arg);

#endif // HALMOS_FCGI_THREAD_POOL_H