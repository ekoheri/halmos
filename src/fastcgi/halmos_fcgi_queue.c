#include "halmos_fcgi_queue.h"
#include "halmos_global.h"
#include "halmos_log.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysinfo.h>

FCGI_TaskQueue global_fcgi_queue;

extern void* fcgi_thread_pool_worker(void *arg);
extern int fcgi_thread_pool_spawn_detached(pthread_t *out_tid, void *(*routine)(void *), void *arg);

static int halmos_fcgi_get_adaptive_timeout(FCGI_TaskQueue *q) {
    if (q->total_workers > q->min_threads_limit) {
        return 10; 
    }
    return 60;     
}

bool fcgi_queue_start(void) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    q->head = q->tail = NULL;
    q->size = 0;
    q->max_queue_limit = g_fcgi_queue_capacity;
    q->active_workers = 0;
    q->total_workers = g_worker_min;
    q->min_threads_limit = g_worker_min;
    q->max_threads_limit = g_worker_max;
    q->scaling_in_progress = 0;
    q->is_running = 1;

    if (pthread_mutex_init(&q->lock, NULL) != 0) return false;
    if (pthread_cond_init(&q->not_empty, NULL) != 0) return false;
    if (pthread_cond_init(&q->exit_cond, NULL) != 0) return false;

    return true;
}

void fcgi_queue_stop(void) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);
    q->is_running = 0;
    pthread_cond_broadcast(&q->not_empty);

    while (q->total_workers > 0) {
        pthread_cond_wait(&q->exit_cond, &q->lock);
    }
    pthread_mutex_unlock(&q->lock);

    pthread_mutex_lock(&q->lock);
    FCGI_Task *curr = q->head;
    q->head = q->tail = NULL;
    q->size = 0;
    pthread_mutex_unlock(&q->lock);

    while (curr) {
        FCGI_Task *tmp = curr;
        curr = curr->next;
        
        // Lepaskan referensi slot sesi di global pool jika task dibuang saat shutdown
        FCGI_Session *session = fcgi_session_slot_get(tmp->session_id);
        if (session) {
            fcgi_session_release(session);
        }
        
        free(tmp);
    }

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->exit_cond);
}

bool fcgi_queue_push(int session_id, FCGI_TaskType type) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);

    if (!q->is_running || q->size >= q->max_queue_limit) {
        write_log_warn_code(WARN_FCGI_QUEUE_FULL, q->size, q->max_queue_limit);
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    FCGI_Task *new_task = malloc(sizeof(FCGI_Task));
    if (!new_task) {
        write_log_error_code(ERR_FCGI_TASK_MEM);
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    // --- AMBIL SESSION DARI GLOBAL POOL & NAIKKAN REF_COUNT ---
    FCGI_Session *session = fcgi_session_slot_get(session_id);
    if (!session) {
        free(new_task);
        pthread_mutex_unlock(&q->lock);
        return false;
    }
    fcgi_session_acquire(session); 
    // -----------------------------------------------------------
    
    new_task->type = type;
    new_task->session_id = session_id; // Cukup simpan ID integer!
    gettimeofday(&new_task->arrival_time, NULL);
    new_task->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = new_task;
    } else {
        q->tail->next = new_task;
        q->tail = new_task;
    }
    q->size++;

    int should_spawn = 0;
    int queue_threshold = q->total_workers * 2; 
    if (queue_threshold < 4) queue_threshold = 4;

    //UPSCALE : Jika ada task baru yang masuk (push) dan ukuran antrean (q->size) 
    // melebihi ambang batas (queue_threshold, yaitu dua kali lipat jumlah worker aktif), 
    // serta jumlah worker belum menyentuh batas maksimal (g_worker_max), 
    // server akan secara otomatis menaikkan q->total_workers++ dan 
    // men-spawn worker baru (fcgi_thread_pool_spawn_detached).
    
    if (q->size > queue_threshold 
        && q->total_workers < q->max_threads_limit 
        && !q->scaling_in_progress) {
        
        q->total_workers++;
        q->scaling_in_progress = 1;
        should_spawn = 1;
    }

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);

    if (should_spawn) {
        pthread_t tid;
        int spawn_res = fcgi_thread_pool_spawn_detached(&tid, fcgi_thread_pool_worker, q);
        if (spawn_res != 0) {
            write_log_error_code(ERR_FCGI_SPAWN_THREAD, strerror(spawn_res));
            pthread_mutex_lock(&q->lock);
            q->total_workers--; 
            pthread_mutex_unlock(&q->lock);
        }

        pthread_mutex_lock(&q->lock);
        q->scaling_in_progress = 0;
        pthread_mutex_unlock(&q->lock);
    }

    return true;
}

FCGI_Task* fcgi_queue_pop(struct timeval *arrival) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);

    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        if (!q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return NULL;
        }

        gettimeofday(&now, NULL);
        int current_timeout = halmos_fcgi_get_adaptive_timeout(q);

        ts.tv_sec = now.tv_sec + current_timeout;
        ts.tv_nsec = (long)(now.tv_usec * 1000);
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int rc = pthread_cond_timedwait(&q->not_empty, &q->lock, &ts);

        if (!q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return NULL;
        }

        //DOWNSCALE : Jika sebuah worker thread menunggu tugas di dalam antrean (pop) hingga 
        // mengalami waktu habis/timeout (ETIMEDOUT), antrean kosong (q->head == NULL), 
        // dan jumlah worker saat ini masih di atas batas minimal (g_worker_min), 
        // maka worker tersebut akan memangkas dirinya sendiri (q->total_workers--) 
        // dan keluar secara anggun untuk menghemat sumber daya sistem.
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return NULL; 
        }
    }

    if (!q->is_running) {
        q->total_workers--;
        pthread_cond_signal(&q->exit_cond);
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }

    FCGI_Task *tmp = q->head;
    if (arrival) *arrival = tmp->arrival_time;

    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->size--;

    pthread_mutex_unlock(&q->lock);
    return tmp;
}