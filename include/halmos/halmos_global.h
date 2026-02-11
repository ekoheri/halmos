#ifndef HALMOS_GLOBAL_H
#define HALMOS_GLOBAL_H

#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_queue.h"

// --- Penampung Hasil Adaptive ---
extern int g_event_batch_size;  // Untuk epoll_wait
extern int g_fcgi_pool_size;    // Untuk FastCGI connection pool
extern int g_worker_max;        // Untuk Thread Worker max
extern int g_worker_min;        // Untuk Thread Worker min
extern int g_queue_capacity;    // Untuk Task Queue limit

// Deklarasikan variabel global untuk :
// 1. menyimpan konfigurasi
extern Config config;

// 2. menyimpan informasi struct event pool
extern struct epoll_event *events;

// 3. menyimoan flag data event pool
extern int epoll_fd;

// 4. menyimpan informasi jumlah maksimum event loop
// sesuaidengan kapasitas Core CPU komputer
// extern int max_event_loop;

// 4. Informasi menyimpan taskqueue
extern TaskQueue global_queue;

// 5. Forward declaration untukworker_thread_pool 
// yang ada di halmos_queue.c
extern void *worker_thread_pool(void *arg);

#endif