#ifndef HALMOS_GLOBAL_H
#define HALMOS_GLOBAL_H

#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_queue.h"

#include <stdint.h>

// --- Penampung Hasil Adaptive ---
// --- 1. DOMAIN CORE / FRONTEND (Klien & Epoll) ---
extern uint32_t g_core_max_fd;       // Maksimal FD untuk epoll client
extern int g_core_queue_capacity;    // Kapasitas Task Queue untuk HTTP request masuk

// --- 2. DOMAIN WORKER THREAD POOL (Shared Workers) ---
extern int g_worker_min;             // Minimal thread pekerja
extern int g_worker_max;             // Maksimal thread pekerja (berdasarkan core CPU)
extern int g_event_batch_size;       // Ukuran batch epoll_wait

// --- 3. DOMAIN BACKEND / FASTCGI UPSTREAM ---
extern int g_fcgi_upstream_slots;    // Total slot koneksi paralel ke FPM (PHP+Rust+Python)
extern int g_fcgi_queue_capacity;    // Batas antrean khusus jika jatah backend penuh

// --- DOMAIN BACKEND UPSTREAM QUOTA untuk (PHP+Rust+Python) ---
extern int g_fcgi_php_quota;
extern int g_fcgi_rust_quota;
extern int g_fcgi_python_quota;

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