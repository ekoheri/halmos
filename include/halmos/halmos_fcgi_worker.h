#ifndef HALMOS_FCGI_WORKER_H
#define HALMOS_FCGI_WORKER_H

#include <stdbool.h>
#include <pthread.h>

// --- 1. STRUKTUR WORKER POOL ---
typedef struct {
    int worker_count;           // Jumlah thread worker yang aktif di dalam pool
    pthread_t *threads;         // Array pointer ke ID thread worker
    volatile bool running;      // Status kontrol untuk menghentikan worker pool secara graceful
} FCGIWorkerPool;

bool halmos_fcgi_worker_pool_init(void);

void halmos_fcgi_worker_pool_stop(void);

void* halmos_fcgi_worker_routine(void *arg);

#endif // HALMOS_FCGI_WORKER_H