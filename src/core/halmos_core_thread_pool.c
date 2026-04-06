#include "halmos_core_thread_pool.h"
#include "halmos_global.h"
#include "halmos_core_event_loop.h"
#include "halmos_http_bridge.h"
#include "halmos_log.h"

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

void mark_worker_idle(TaskQueue *q);

/********************************************************************
 * halmos_worker_routine() -> [SIKLUS KERJA KOKI]
 * Persis Logika Boss: Ambil -> Masak -> Beresin Meja
 ********************************************************************/
void *core_thread_pool_worker(void *arg) {
    (void)arg;
    while (1) {
        struct timeval arrival;
        
        // 1. Ambil tugas (File Descriptor) dari antrean
        int sock_client = queue_pop(&global_queue, &arrival);
        
        if (sock_client < 0) continue;

        // Catat statistik global
        global_telemetry.total_requests++;

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        // 2. PROSES REQUEST (Dispatcher Utama)
        // Boss, urusan SSL Handshake, Dekripsi, dan Deteksi Protokol 
        // semuanya kita pindah ke dalam bridge_dispatch().
        int status = http_bridge_dispatch(sock_client);

        // 3. EVALUASI HASIL DISPATCH
        if (status == 1) {
            // Status 1: Keep-Alive atau SSL Handshake butuh data lagi (EAGAIN)
            // Ambil dari event_loop.c
            event_loop_rearm_epoll(sock_client);
        } else {
            // Status 0 atau -1: Koneksi selesai atau Error
            // cleanup_connection_properly ada di halmos_event_loop.c

            global_telemetry.active_connections--;
            event_loop_cleanup_connection(sock_client);
        }

        // --- TELEMETRY & LOGGING ---
        clock_gettime(CLOCK_MONOTONIC, &end);
        global_telemetry.last_latency_ms = hitung_durasi(start, end);
        
        if (global_telemetry.total_requests % 100 == 0) {
            update_mem_usage();
        }
        write_log_telemetry();

        // 4. Tandai koki (thread) kembali IDLE
        mark_worker_idle(&global_queue);
    }
    return NULL;
}

/********************************************************************
 * mark_worker_idle()
 * ---------------------------------------------------------------
 * Analogi:
 * Setelah koki selesai masak:
 *
 * Dia laporan ke manajer:
 * "Saya sudah selesai, siap terima pesanan lagi."
 *
 * Status active_workers dikurangi satu.
 ********************************************************************/
void mark_worker_idle(TaskQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->active_workers--;
    pthread_mutex_unlock(&q->lock);
}
