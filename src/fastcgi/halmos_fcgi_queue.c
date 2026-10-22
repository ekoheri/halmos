#include "halmos_fcgi_queue.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysinfo.h>

FCGITaskQueue global_fcgi_queue;

extern void* halmos_fcgi_worker_routine(void *arg);
extern int halmos_fcgi_spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg);

// Timeout adaptif yang lebih aman (tidak terlalu ekstrem turun ke 0)
static int halmos_fcgi_get_adaptive_timeout(FCGITaskQueue *q) {
    // Karena fungsi ini dipanggil saat q->head == NULL (antrean kosong), 
    // kita bisa memberikan timeout idle standar yang sehat (misal 30 detik) 
    // atau mendasarkannya pada total_workers vs min_threads.
    if (q->total_workers > q->min_threads_limit) {
        return 10; // Worker ekstra lebih cepat turun jika idle
    }
    return 60;     // Worker minimal bertahan lebih lama
}

bool halmos_fcgi_queue_init(int min_limit, int max_limit, int max_queue_size) {
    FCGITaskQueue *q = &global_fcgi_queue;
    q->head = q->tail = NULL;
    q->size = 0;
    q->max_queue_limit = max_queue_size;
    q->active_workers = 0;
    q->total_workers = min_limit;
    q->min_threads_limit = min_limit;
    q->max_threads_limit = max_limit;
    q->scaling_in_progress = 0;
    q->is_running = 1;

    if (pthread_mutex_init(&q->lock, NULL) != 0) return false;
    if (pthread_cond_init(&q->not_empty, NULL) != 0) return false;
    if (pthread_cond_init(&q->exit_cond, NULL) != 0) return false;

    return true;
}

void halmos_fcgi_queue_destroy(void) {
    FCGITaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);
    q->is_running = 0;
    pthread_cond_broadcast(&q->not_empty);

    while (q->total_workers > 0) {
        pthread_cond_wait(&q->exit_cond, &q->lock);
    }
    pthread_mutex_unlock(&q->lock);

    pthread_mutex_lock(&q->lock);
    FCGITask *curr = q->head;
    q->head = q->tail = NULL;
    q->size = 0;
    pthread_mutex_unlock(&q->lock);

    while (curr) {
        FCGITask *tmp = curr;
        curr = curr->next;
        
        if (tmp->session) {
            halmos_fcgi_session_destroy(tmp->session);
            tmp->session = NULL;
        }
        
        free(tmp);
    }

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->exit_cond);
}

bool halmos_fcgi_queue_push(HalmosFCGISession *session, FCGI_TaskType type) {
    FCGITaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);

    if (!q->is_running || q->size >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    FCGITask *new_task = malloc(sizeof(FCGITask));
    if (!new_task) {
        pthread_mutex_unlock(&q->lock);
        return false;
    }

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
        if (halmos_fcgi_spawn_detached_worker(&tid, halmos_fcgi_worker_routine, q) != 0) {
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

FCGITask* halmos_fcgi_queue_pop(struct timeval *arrival) {
    FCGITaskQueue *q = &global_fcgi_queue;
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

    FCGITask *tmp = q->head;
    if (arrival) *arrival = tmp->arrival_time;

    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->size--;

    pthread_mutex_unlock(&q->lock);
    return tmp;
}

void halmos_fcgi_queue_broadcast(void) {
    FCGITaskQueue *q = &global_fcgi_queue;
    pthread_mutex_lock(&q->lock);
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}