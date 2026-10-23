#include "halmos_fcgi_thread_pool.h"
#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_event_loop.h"
#include "halmos_log.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>

static FCGI_WorkerPool fcgi_worker_pool;

bool fcgi_thread_pool_start(void) {
    // Menggunakan baseline worker minimum dari pilar CPU
    int min_workers = g_worker_min;
    if (min_workers < 2) min_workers = 2;
    
    // Menggunakan plafon worker maksimum dari pilar CPU
    int max_workers = g_worker_max;
    if (max_workers < min_workers) max_workers = min_workers * 2;

    fcgi_worker_pool.min_workers = min_workers;
    fcgi_worker_pool.max_workers = max_workers;
    fcgi_worker_pool.running = true;

    for (int i = 0; i < min_workers; i++) {
        pthread_t tid;
        if (fcgi_thread_pool_spawn_detached(&tid, fcgi_thread_pool_worker, &global_fcgi_queue) != 0) {
            fcgi_worker_pool.running = false;
            //Pemanggilan fcgi_queue_stop() didalam loop ini
            // berfungsi sebagai pengaman darurat (abort/cleanup) 
            // jika pembuatan thread gagal di tengah jalan saat server dinyalakan.
            fcgi_queue_stop();
            return false;
        }
    }

    return true;
}

void fcgi_thread_pool_stop(void) {
    fcgi_worker_pool.running = false;
}

void* fcgi_thread_pool_worker(void *arg) {
    //FCGI_TaskQueue *q = (FCGI_TaskQueue *)arg;
    (void)arg;
    while (fcgi_worker_pool.running) {
        struct timeval arrival;
        FCGI_Task *task = fcgi_queue_pop(&arrival);
        
        if (!task) {
            break; // Keluar thread jika downscale / shutdown
        }

        FCGI_Session *session = task->session;
        if (session) {
            if (task->type == FCGI_TASK_PROCESS_READ) {
                bool active = fcgi_fsm_step(session);
                if (!active) {
                    // Berikan jeda atau pastikan lock sesi aman sebelum destroy
                    pthread_mutex_lock(&session->lock);
                    fcgi_event_loop_del(session->fpm_fd);
                    pthread_mutex_unlock(&session->lock);
                    
                    // Jangan langsung destroy jika h2 stream masih butuh flush, 
                    // atau pastikan cleanup dipanggil lewat jalur yang aman.
                    fcgi_session_destroy(session);
                }
            } else if (task->type == FCGI_TASK_DISCONNECT) {
                fcgi_event_loop_del(session->fpm_fd);
                fcgi_session_destroy(session);
            }
        }

        // Bebaskan memori task dengan aman setelah eksekusi tuntas
        free(task);
    }

    return NULL;
}

bool fcgi_thread_pool_is_running(void) {
    return fcgi_worker_pool.running;
}

int fcgi_thread_pool_spawn_detached(pthread_t *out_tid, void *(*routine)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int ret = pthread_create(out_tid, &attr, routine, arg);
    pthread_attr_destroy(&attr);
    return ret;
}
