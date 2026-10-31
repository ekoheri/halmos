#include "halmos_fcgi_thread_pool.h"
#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_event_loop.h"
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
    int min_workers = g_worker_min;
    if (min_workers < 2) min_workers = 2;
    
    int max_workers = g_worker_max;
    if (max_workers < min_workers) max_workers = min_workers * 2;

    fcgi_worker_pool.min_workers = min_workers;
    fcgi_worker_pool.max_workers = max_workers;
    fcgi_worker_pool.running = true;

    fprintf(stderr, "[FCGI_POOL_DEBUG] Starting FastCGI thread pool: min_workers=%d, max_workers=%d\n", min_workers, max_workers);

    for (int i = 0; i < min_workers; i++) {
        pthread_t tid;
        if (fcgi_thread_pool_spawn_detached(&tid, fcgi_thread_pool_worker, &global_fcgi_queue) != 0) {
            fprintf(stderr, "[FCGI_POOL_DEBUG] ERROR: Failed to spawn worker thread #%d\n", i);
            fcgi_worker_pool.running = false;
            fcgi_queue_stop();
            return false;
        }
    }

    fprintf(stderr, "[FCGI_POOL_DEBUG] FastCGI thread pool successfully started.\n");
    return true;
}

void fcgi_thread_pool_stop(void) {
    fprintf(stderr, "[FCGI_POOL_DEBUG] Stopping FastCGI thread pool...\n");
    fcgi_worker_pool.running = false;
}

void* fcgi_thread_pool_worker(void *arg) {
    (void)arg;
    fprintf(stderr, "[FCGI_WORKER_DEBUG] Worker thread spawned and entering loop (tid=%lu)\n", (unsigned long)pthread_self());

    while (fcgi_worker_pool.running) {
        struct timeval arrival;
        FCGI_Task *task = fcgi_queue_pop(&arrival);
        
        if (!task) {
            fprintf(stderr, "[FCGI_WORKER_DEBUG] Worker thread received NULL task, exiting loop (tid=%lu)\n", (unsigned long)pthread_self());
            break; 
        }

        FCGI_Session *session = task->session;
        FCGI_TaskType task_type = task->type;
        
        free(task); 

        if (!session) {
            continue;
        }

        pthread_mutex_lock(&session->lock);
        if (session->fpm_fd == -99) {
            pthread_mutex_unlock(&session->lock);
            // Lepaskan kepemilikan task worker dari session
            fcgi_session_release(session);
            continue;
        }

        int sock_c = session->sock_client;
        bool is_h2 = session->is_http2;
        pthread_mutex_unlock(&session->lock);

        halmos_conn_t *conn = core_conn_t_get(sock_c);
        if (!conn) {
            // Ganti session_destroy dengan session_release
            fcgi_session_release(session);
            continue;
        }

        core_conn_t_lock(conn);

        pthread_mutex_lock(&session->lock);
        if (session->fpm_fd == -99) {
            pthread_mutex_unlock(&session->lock);
            core_conn_t_unlock(conn);
            fcgi_session_release(session);
            continue;
        }
        pthread_mutex_unlock(&session->lock);

        if (task_type == FCGI_TASK_PROCESS_READ) {
            bool active = false;

            if (is_h2) {
                active = fcgi_fsm_step_http2(session);
            } else {
                active = fcgi_fsm_step_http1(session);
            }

            if (!active) {
                pthread_mutex_lock(&session->lock);
                
                int target_fd = session->fpm_fd;
                if (target_fd != -99 && target_fd != -1) {
                    fcgi_event_loop_del(target_fd);
                }

                pthread_mutex_unlock(&session->lock);
                
                if (is_h2) {
                    fcgi_session_release(session);
                } else {
                    if (sock_c > 0) {
                        core_event_loop_rearm_epoll_ex(sock_c, EPOLLOUT | EPOLLIN);
                    }
                }
            }
        } else if (task_type == FCGI_TASK_DISCONNECT) {
            pthread_mutex_lock(&session->lock);
            int target_fd = session->fpm_fd;
            if (target_fd != -99 && target_fd != -1) {
                fcgi_event_loop_del(target_fd);
                session->fpm_fd = -1;
            }
            pthread_mutex_unlock(&session->lock);
            
            if (is_h2) {
                fcgi_session_release(session);
            }
        }

        core_conn_t_unlock(conn);

        // --- PENTING: Lepaskan referensi yang dipegang oleh worker task ini ---
        // Akan berdapak [UPSTREAM_FATAL] fcgi_upstream_acquire FAILED! Target IP: 127.0.0.1, Port: 9000 (Pool Exhausted!)
        // Ketika diuji wrk
        fcgi_session_release(session);
    }

    fprintf(stderr, "[FCGI_WORKER_DEBUG] Worker thread routine terminated (tid=%lu)\n", (unsigned long)pthread_self());
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