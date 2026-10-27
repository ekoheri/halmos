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
        if (session) {
            // === GUARD : CEGAH ACCESS FREED MEMORY LEWAT REGISTRY ===
            if (!fcgi_registry_is_valid(session)) {
                // Sesi sudah lenyap / didestruksi oleh thread lain. Abaikan task!
                free(task);
                continue;
            }

            // === 1. AMBIL DAN VALIDASI KONEKSI DARI CONNECTION TABLE ===
            int client_sock = session->sock_client;
            uint32_t client_gen = session->client_generation;

            halmos_conn_t *conn = core_conn_t_get(client_sock);
            if (!conn || !core_conn_t_is_valid(client_sock, client_gen)) {
                fprintf(stderr, "[FCGI_WORKER_DEBUG] Stale client connection detected on socket %d (Gen: %u). Dropping task type=%d\n", 
                          client_sock, client_gen, task->type);
                
                // HANYA DESTROY JIKA HTTP/2. HTTP/1 DI-HANDLE OLEH HTTP1 MANAGER!
                if (session->is_http2) {
                    fcgi_session_destroy(session);
                } else {
                    pthread_mutex_lock(&session->lock);
                    session->fpm_fd = -99;
                    pthread_mutex_unlock(&session->lock);
                }
                
                free(task);
                continue;
            }

            // === 2. AKUISISI KUNCI KONEKSI (Mencegah Cleanup Bersamaan) ===
            core_conn_t_lock(conn);

            // Double-check setelah dikunci
            if (!core_conn_t_is_valid(client_sock, client_gen)) {
                core_conn_t_unlock(conn);

                if (session->is_http2) {
                    fcgi_session_destroy(session);
                } else {
                    pthread_mutex_lock(&session->lock);
                    session->fpm_fd = -99;
                    pthread_mutex_unlock(&session->lock);
                }
                free(task);
                continue;
            }

            // === 3. GUARD MUTLAK: CEGAH DOUBLE FREE & STALE SESSION ===
            pthread_mutex_lock(&session->lock);
            if (session->fpm_fd == -99) {
                fprintf(stderr, "[FCGI_WORKER_DEBUG] WARNING: Stale session detected (fpm_fd == -99). Dropping task type=%d\n", task->type);
                pthread_mutex_unlock(&session->lock);
                core_conn_t_unlock(conn);
                free(task);
                continue;
            }
            pthread_mutex_unlock(&session->lock);

            // Simpan flag protokol secara lokal di awal
            bool is_h2 = session->is_http2;

            if (task->type == FCGI_TASK_PROCESS_READ) {
                fprintf(stderr, "[FCGI_WORKER_DEBUG] Processing FCGI_TASK_PROCESS_READ | session=%p, is_h2=%d, fpm_fd=%d\n", 
                        (void*)session, is_h2, session->fpm_fd);

                bool active = false;

                if (is_h2) {
                    active = fcgi_fsm_step_http2(session);
                } else {
                    active = fcgi_fsm_step_http1(session);
                }

                fprintf(stderr, "[FCGI_WORKER_DEBUG] FSM step executed. active=%d (session=%p)\n", active, (void*)session);

                if (!active) {
                    pthread_mutex_lock(&session->lock);
                    int target_fd = session->fpm_fd;
                    if (target_fd != -99 && target_fd != -1) {
                        fprintf(stderr, "[FCGI_WORKER_DEBUG] Removing fpm_fd=%d from upstream epoll poller\n", target_fd);
                        fcgi_event_loop_del(target_fd);
                        if (!is_h2) {
                            session->fpm_fd = -1; // Hanya untuk HTTP/1 yang diserahkan ke HTTP/1 Manager
                        }
                    }
                    
                    pthread_mutex_unlock(&session->lock);
                    
                    if (is_h2) {
                        fprintf(stderr, "[FCGI_WORKER_DEBUG] Destroying HTTP/2 FastCGI session immediately (%p)\n", (void*)session);
                        fcgi_session_destroy(session);
                    } else {
                        fprintf(stderr, "[FCGI_WORKER_DEBUG] HTTP/1 FastCGI session handed over to HTTP/1 manager for flushing (session=%p, client_sock=%d)\n", (void*)session, client_sock);
                        
                        // === KUNCI UTAMA: BANGUNKAN CORE EVENT LOOP CLIENT SOCKET ===
                        if (client_sock > 0) {
                            core_event_loop_rearm_epoll_ex(client_sock, EPOLLOUT | EPOLLIN);
                        }
                    }
                }
            } else if (task->type == FCGI_TASK_DISCONNECT) {
                fprintf(stderr, "[FCGI_WORKER_DEBUG] Processing FCGI_TASK_DISCONNECT | session=%p, fpm_fd=%d\n", (void*)session, session->fpm_fd);

                pthread_mutex_lock(&session->lock);
                int target_fd = session->fpm_fd;
                if (target_fd != -99 && target_fd != -1) {
                    fprintf(stderr, "[FCGI_WORKER_DEBUG] Deleting disconnected fpm_fd=%d from epoll\n", target_fd);
                    fcgi_event_loop_del(target_fd);
                    session->fpm_fd = -1;
                }
                pthread_mutex_unlock(&session->lock);
                
                if (is_h2) {
                    fcgi_session_destroy(session);
                }
            }

            // === 4. LEPASKAN KUNCI KONEKSI ===
            core_conn_t_unlock(conn);
        }

        free(task);
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