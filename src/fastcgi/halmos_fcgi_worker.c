#include "halmos_fcgi_worker.h"
#include "halmos_fcgi_fsm.h"

#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_http2_core.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_poller.h"
#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_sec_tls.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>

// Variabel global untuk Worker Pool
static FCGIWorkerPool fcgi_worker_pool;

// Helper untuk mengecek status pool dari modul lain (seperti queue)
bool halmos_fcgi_is_running(void) {
    return fcgi_worker_pool.running;
}

bool halmos_fcgi_worker_pool_init(void) {
    // 1. Ambil nilai secara adaptif dari variabel global
    int worker_count = g_fcgi_pool_size;

    // 2. Internal Safety Clamp / Sanity Check
    if (worker_count < 2) {
        worker_count = 2; // Batas minimal aman agar poller tetap punya napas
    }
    if (worker_count > g_worker_max) {
        worker_count = g_worker_max; // Jangan melebihi ceiling hardware yang terdeteksi
    }

    fcgi_worker_pool.worker_count = worker_count;
    fcgi_worker_pool.running = true;

    fcgi_worker_pool.threads = (pthread_t*)malloc(sizeof(pthread_t) * worker_count);
    if (!fcgi_worker_pool.threads) {
        fprintf(stderr, "[FCGI WORKER] Memory allocation failed for worker threads!\n");
        return false;
    }

    for (int i = 0; i < worker_count; i++) {
        if (pthread_create(&fcgi_worker_pool.threads[i], NULL, halmos_fcgi_worker_routine, NULL) != 0) {
            fcgi_worker_pool.running = false;
            // Cleanup thread yang sudah terlanjur dibuat
            for (int j = 0; j < i; j++) {
                pthread_cancel(fcgi_worker_pool.threads[j]);
            }
            free(fcgi_worker_pool.threads);
            return false;
        }
    }

    return true;
}

void halmos_fcgi_worker_pool_stop(void) {
    fprintf(stderr, "[FCGI_WORKER_DEBUG] Stopping worker pool and forcing active socket closure...\n");
    fcgi_worker_pool.running = false;

    // 1. Tutup paksa semua fpm_fd yang masih aktif/tersisa di sesi agar operasi recv/poll unblock seketika
    // (Asumsikan Anda memiliki fungsi untuk iterasi sesi aktif atau membersihkannya dari connection table/registry)
    // Jika sesi dikelola via antrean atau tabel koneksi, tutup fd-nya di sini.
    
    // 2. Bangunkan semua worker yang sedang tertahan di antrean queue
    halmos_fcgi_queue_broadcast();

    if (fcgi_worker_pool.threads) {
        for (int i = 0; i < fcgi_worker_pool.worker_count; i++) {
            // Jika thread menggunakan pthread_cancel sebagai opsi darurat unblock:
            // pthread_cancel(fcgi_worker_pool.threads[i]);
            
            int rc = pthread_join(fcgi_worker_pool.threads[i], NULL);
            if (rc != 0) {
                fprintf(stderr, "[FCGI_WORKER_DEBUG] WARNING: Failed to join worker thread %d!\n", i);
            }
        }
        free(fcgi_worker_pool.threads);
        fcgi_worker_pool.threads = NULL;
    }
    fprintf(stderr, "[FCGI_WORKER_DEBUG] Worker pool successfully stopped and joined.\n");
}

void* halmos_fcgi_worker_routine(void *arg) {
    (void)arg;

    while (fcgi_worker_pool.running) {
        // Ambil task dari antrean secara thread-safe (blocking via condition variable)
        FCGITask *task = halmos_fcgi_queue_pop();
        if (!task) continue; // Jika NULL karena shutdown, loop akan aman mendeteksi running = false

        HalmosFCGISession *session = task->session;
        if (session) {
            if (task->type == FCGI_TASK_PROCESS_READ) {
                // Eksekusi langkah FSM
                bool active = halmos_fcgi_fsm_step(session);
                if (!active) {
                    // Sesi selesai atau error, hapus dari poller dan hancurkan
                    halmos_fcgi_poller_del(session->fpm_fd);
                    halmos_fcgi_session_destroy(session);
                }
            } else if (task->type == FCGI_TASK_DISCONNECT) {
                // Koneksi backend terputus/error
                halmos_fcgi_poller_del(session->fpm_fd);
                halmos_fcgi_session_destroy(session);
            }
        }

        free(task);
    }

    return NULL;
}

