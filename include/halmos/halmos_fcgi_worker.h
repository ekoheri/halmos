#ifndef HALMOS_FCGI_WORKER_H
#define HALMOS_FCGI_WORKER_H

#include <stdbool.h>
#include <pthread.h>
#include "halmos_fcgi_session.h" // Menggunakan struktur sesi FSM

// --- 1. STRUKTUR WORKER POOL ---
typedef struct {
    int worker_count;           // Jumlah thread worker yang aktif di dalam pool
    pthread_t *threads;         // Array pointer ke ID thread worker
    volatile bool running;      // Status kontrol untuk menghentikan worker pool secara graceful
} FCGIWorkerPool;

// --- 2. PROTOTIPE FUNGSI INTERFACE ---

/**
 * Menginisialisasi dan meluncurkan Worker Thread Pool sejumlah worker_count.
 * @param worker_count Jumlah thread worker yang akan dialokasikan
 * @return true jika berhasil diinisialisasi, false jika gagal.
 */
bool halmos_fcgi_worker_pool_init(void);

/**
 * Menghentikan seluruh thread worker dengan aman (graceful stop) dan membersihkan resource.
 */
void halmos_fcgi_worker_pool_stop(void);

/**
 * Rutinitas utama yang dijalankan oleh setiap worker thread (target dari pthread_create).
 * Berisi loop mengambil task dari queue dan mengeksekusi FSM sesi terkait.
 */
void* halmos_fcgi_worker_routine(void *arg);

/**
 * Mengeksekusi langkah perpindahan status Finite State Machine (FSM) untuk sebuah sesi.
 * Menangani pembacaan STDOUT dari PHP-FPM, pemrosesan header, dan pengiriman respons ke klien.
 * @param session Pointer ke sesi FSM yang sedang diproses
 * @return true jika sesi masih berlanjut, false jika sesi selesai atau mengalami error.
 */
bool halmos_fcgi_fsm_step(HalmosFCGISession *session);

#endif // HALMOS_FCGI_WORKER_H