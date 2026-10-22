#include "halmos_fcgi_worker.h"
#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_poller.h"
#include "halmos_log.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>

static FCGIWorkerPool fcgi_worker_pool;

bool halmos_fcgi_is_running(void) {
    return fcgi_worker_pool.running;
}

int halmos_fcgi_spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int ret = pthread_create(out_tid, &attr, routine, arg);
    pthread_attr_destroy(&attr);
    return ret;
}

bool halmos_fcgi_worker_pool_init(void) {
    int min_workers = g_fcgi_pool_size;
    if (min_workers < 2) min_workers = 2;
    
    int max_workers = g_worker_max;
    if (max_workers < min_workers) max_workers = min_workers * 2;

    fcgi_worker_pool.min_workers = min_workers;
    fcgi_worker_pool.max_workers = max_workers;
    fcgi_worker_pool.running = true;

    for (int i = 0; i < min_workers; i++) {
        pthread_t tid;
        if (halmos_fcgi_spawn_detached_worker(&tid, halmos_fcgi_worker_routine, &global_fcgi_queue) != 0) {
            fcgi_worker_pool.running = false;
            halmos_fcgi_queue_destroy();
            return false;
        }
    }

    return true;
}

void halmos_fcgi_worker_pool_stop(void) {
    fcgi_worker_pool.running = false;
    //halmos_fcgi_queue_destroy();
}

void* halmos_fcgi_worker_routine(void *arg) {
    //FCGITaskQueue *q = (FCGITaskQueue *)arg;
    (void)arg;
    while (fcgi_worker_pool.running) {
        struct timeval arrival;
        FCGITask *task = halmos_fcgi_queue_pop(&arrival);
        
        if (!task) {
            break; // Keluar thread jika downscale / shutdown
        }

        HalmosFCGISession *session = task->session;
        if (session) {
            if (task->type == FCGI_TASK_PROCESS_READ) {
                bool active = halmos_fcgi_fsm_step(session);
                if (!active) {
                    // Berikan jeda atau pastikan lock sesi aman sebelum destroy
                    pthread_mutex_lock(&session->lock);
                    halmos_fcgi_poller_del(session->fpm_fd);
                    pthread_mutex_unlock(&session->lock);
                    
                    // Jangan langsung destroy jika h2 stream masih butuh flush, 
                    // atau pastikan cleanup dipanggil lewat jalur yang aman.
                    halmos_fcgi_session_destroy(session);
                }
            } else if (task->type == FCGI_TASK_DISCONNECT) {
                halmos_fcgi_poller_del(session->fpm_fd);
                halmos_fcgi_session_destroy(session);
            }
        }

        // Bebaskan memori task dengan aman setelah eksekusi tuntas
        free(task);
    }

    return NULL;
}