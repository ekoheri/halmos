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

// Timeout adaptif yang lebih aman (tidak terlalu ekstrem turun ke 0)
static int halmos_fcgi_get_adaptive_timeout(FCGI_TaskQueue *q) {
    // Karena fungsi ini dipanggil saat q->head == NULL (antrean kosong), 
    // kita bisa memberikan timeout idle standar yang sehat (misal 30 detik) 
    // atau mendasarkannya pada total_workers vs min_threads.
    if (q->total_workers > q->min_threads_limit) {
        return 10; // Worker ekstra lebih cepat turun jika idle
    }
    return 60;     // Worker minimal bertahan lebih lama
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

    // PERUBAHAN: Berikan error code jika gagal inisialisasi primitif sinkronisasi
    if (pthread_mutex_init(&q->lock, NULL) != 0) {
        write_log_error_code(ERR_FCGI_QUEUE_INIT);
        return false;
    }
    if (pthread_cond_init(&q->not_empty, NULL) != 0) {
        write_log_error_code(ERR_FCGI_QUEUE_INIT);
        return false;
    }
    if (pthread_cond_init(&q->exit_cond, NULL) != 0) {
        write_log_error_code(ERR_FCGI_QUEUE_INIT);
        return false;
    }

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
        
        if (tmp->session) {
           fcgi_session_release(tmp->session);
            tmp->session = NULL;
        }
        
        free(tmp);
    }

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->exit_cond);
}

bool fcgi_queue_push(FCGI_Session *session, FCGI_TaskType type) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);

    if (!q->is_running || q->size >= q->max_queue_limit) {
        write_log_warn_code(WARN_FCGI_QUEUE_FULL, q->size, q->max_queue_limit);
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    FCGI_Task *new_task = malloc(sizeof(FCGI_Task));
    if (!new_task) {
        write_log_error_code(ERR_FCGI_QUEUE_MEM);
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    // --- TAMBAHAN UNTUK ATOMIC REFERENCE COUNTING ---
    fcgi_session_acquire(session); // Naikkan ref_count karena session masuk ke antrean worker
    // ------------------------------------------------
    
    new_task->type = type;
    new_task->session = session;
    gettimeofday(&new_task->arrival_time, NULL);
    new_task->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = new_task;
    } else {
        q->tail->next = new_task;
        q->tail = new_task;
    }
    q->size++;

    // LOGIKA UPSCALE AMAN (Batasi step penambahan 1 thread per push untuk hindari race condition pthread_create)
    int should_spawn = 0;
    // Ubah ambang batas agar lebih responsif: upscale jika antrean melewati jumlah total worker aktif saat ini
    int queue_threshold = q->total_workers * 2; 
    if (queue_threshold < 4) queue_threshold = 4;

    if (q->size > queue_threshold 
        && q->total_workers < q->max_threads_limit 
        && !q->scaling_in_progress) {
        
        q->total_workers++;
        q->scaling_in_progress = 1;
        should_spawn = 1;
    }

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);

    // Spawn di luar lock mutex queue
    if (should_spawn) {
        pthread_t tid;
        if (fcgi_thread_pool_spawn_detached(&tid, fcgi_thread_pool_worker, q) != 0) {
            pthread_mutex_lock(&q->lock);
            q->total_workers--; // Kembalikan jika gagal
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
        ts.tv_nsec = now.tv_usec * 1000;
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

        // DOWNSCALE AMAN (Hanya jika worker di atas min dan benar-benar timeout idle)
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return NULL; // Keluar thread mandiri secara aman
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

void fcgi_queue_broadcast(void) {
    FCGI_TaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}