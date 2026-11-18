#include "halmos_core_queue.h"
#include "halmos_global.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_config.h"
#include "halmos_core_thread_pool.h"
#include "halmos_log.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h> 

// Pemilik variabel global global_queue
TaskQueue global_queue;

/********************************************************************
- core_queue_init() - Mengambil parameter langsung dari g_adaptive
 ********************************************************************/
void core_queue_init(void) {
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    global_queue.max_queue_limit = adaptive_hw_aware.core_queue_capacity; // Ambil dari Master Struct
    global_queue.active_workers = 0;
    global_queue.total_workers = adaptive_hw_aware.worker_min;           // Ambil dari Master Struct
    global_queue.min_threads_limit = adaptive_hw_aware.worker_min;       // Ambil dari Master Struct
    global_queue.max_threads_limit = adaptive_hw_aware.worker_max;       // Ambil dari Master Struct
    global_queue.scaling_in_progress = 0;
    global_queue.is_running = 1; 
    
    pthread_mutex_init(&global_queue.lock, NULL);
    pthread_cond_init(&global_queue.cond, NULL);
    pthread_cond_init(&global_queue.exit_cond, NULL);
}

/********************************************************************
- core_queue_destroy() - Langsung membersihkan global_queue
 ********************************************************************/
void core_queue_destroy(void) {
    pthread_mutex_lock(&global_queue.lock);
    Task *curr = global_queue.head;
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    pthread_mutex_unlock(&global_queue.lock);

    while (curr) {
        Task *tmp = curr;
        curr = curr->next;
        if (tmp->event.fd >= 0) {
            core_conn_t_deactivate(tmp->event.fd);
            close(tmp->event.fd);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond);
    pthread_cond_destroy(&global_queue.exit_cond);
}

/********************************************************************
 * queue_push()
 ********************************************************************/
int core_queue_push(TaskQueue *q, halmos_event_t event_item) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Safety Check: Kapasitas Antrian
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        write_log_error_code(ERR_CORE_QUEUE_CAPACITY, event_item.fd, event_item.generation);
        return -1; 
    }

    // 2. Alokasi Task menggunakan malloc per task
    Task *new_task = malloc(sizeof(Task));
    if (!new_task) {
        pthread_mutex_unlock(&q->lock);
        return -2; 
    }

    new_task->event = event_item;
    gettimeofday(&new_task->arrival_time, NULL);
    new_task->next = NULL;

    // 3. Masukkan ke Antrean
    if (q->tail == NULL) {
        q->head = q->tail = new_task;
    } else {
        q->tail->next = new_task;
        q->tail = new_task;
    }
    q->count++;

    // 4. LOGIKA UPSCALING
    AdaptivePolicy policy = core_adaptive_get_policy();
    int queue_threshold = q->max_queue_limit * policy.threshold_ratio;
    int spawn_count = 0;

    if (q->count > queue_threshold 
        && q->total_workers < q->max_threads_limit 
        && !q->scaling_in_progress) {

        int available_slots = q->max_threads_limit - q->total_workers;
        int spawn_step = policy.spawn_step;

        spawn_count = (available_slots < spawn_step) ? available_slots : spawn_step;

        q->total_workers += spawn_count;
        q->scaling_in_progress = 1;
    }

    // 5. Bangunkan thread
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);

    // === Spawn thread SETELAH lock dilepas ===
    if (spawn_count > 0) {
        int actually_spawned = core_thread_pool_spawn_workers(spawn_count);

        if (actually_spawned < spawn_count) {
            pthread_mutex_lock(&q->lock);
            q->total_workers -= (spawn_count - actually_spawned);
            pthread_mutex_unlock(&q->lock);
        }

        pthread_mutex_lock(&q->lock);
        q->scaling_in_progress = 0;
        pthread_mutex_unlock(&q->lock);
    }

    return 0;
}

/********************************************************************
 * queue_pop()
 ********************************************************************/
int core_queue_pop(TaskQueue *q, halmos_event_t *out_event, struct timeval *arrival) {
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    // Worker terus mengambil task selama antrean belum kosong, 
    // ATAU jika server masih running. Jika server stop tapi task masih ada, 
    // worker tetap harus melahap task tersebut sampai habis!
    while (q->head == NULL) {
        if (!q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        gettimeofday(&now, NULL);

        AdaptivePolicy policy = core_adaptive_get_policy();
        int current_timeout = policy.timeout_idle;

        ts.tv_sec = now.tv_sec + current_timeout;
        ts.tv_nsec = now.tv_usec * 1000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        
        if (!q->is_running && q->head == NULL) { // Hanya keluar jika kosong & stop
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        // === LOGIKA DOWNSCALING (DETACHED WORKER) ===
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit && q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -3;
        }
    }

    // HAPUS atau sesuaikan pengecekan `if (!q->is_running)` di sini, 
    // karena jika q->head != NULL, kita ingin task-nya tetap dieksekusi 
    // meskipun q->is_running sudah bernilai 0 (proses draining).

    Task *tmp = q->head;
    
    if (out_event) {
        *out_event = tmp->event;
    }
    int sock = tmp->event.fd;
    *arrival = tmp->arrival_time;
   
    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->count--;

    atomic_fetch_add(&q->active_workers, 1); 
 
    // Bebaskan memori task menggunakan free()
    free(tmp);

    pthread_mutex_unlock(&q->lock);

    return sock;
}
