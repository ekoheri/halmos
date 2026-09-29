#include "halmos_core_queue.h"
#include "halmos_global.h"
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

static void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size);
static int spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg);
static int get_adaptive_timeout(TaskQueue *q);

void core_queue_thread_worker_start(void) {
    // Inisialisasi struct antrean global
    init_queue(&global_queue, g_worker_min, g_worker_max, g_queue_capacity);

    int initial_workers = g_worker_min;
    
    // Buat worker thread sejumlah g_worker_min dengan status DETACHED
    for (int i = 0; i < initial_workers; i++) {
        pthread_t tid;
        if (spawn_detached_worker(&tid, core_thread_pool_worker, &global_queue) != 0) {
            write_log_error("[ERR] Failed to create initial worker thread %d", i);
        }
    }
    
    write_log("[QUEUE] Thread pool started dynamically with %d workers (DETACHED mode).", initial_workers);
}

/********************************************************************
 * queue_push()
 ********************************************************************/
int core_queue_push(TaskQueue *q, halmos_event_t event_item) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Safety Check: Kapasitas Parkir
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        write_log_error("[QUEUE] Capacity reached! Rejecting client FD %d (Gen: %u)", 
                        event_item.fd, event_item.generation);
        return -1; 
    }

    // 2. Alokasi Task
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
    /*
    Untuk uji coba misalkan menggunakan :
      wrk -t8 -c1500 -d30s https://localhost:8080/index.html
      queue_threshold = gunakan 5% saja (0.05)
      tetapi kalau di server production,queue_threshold buat saja 50% (0.5) ya
    */
    //int queue_threshold = q->max_queue_limit * 0.05;//ini untuk uji saja
    int queue_threshold = q->max_queue_limit * 0.5; // ini di server production

    int spawn_count = 0;

    if (q->count > queue_threshold 
        && q->total_workers < q->max_threads_limit 
        && !q->scaling_in_progress) {

        int available_slots = q->max_threads_limit - q->total_workers;
        spawn_count = (available_slots < 4) ? available_slots : 4;

        q->total_workers += spawn_count;
        q->scaling_in_progress = 1;
    }

    // 5. Bangunkan thread
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);

    // === Spawn thread SETELAH lock dilepas ===
    if (spawn_count > 0) {
        int actually_spawned = 0;

        for (int i = 0; i < spawn_count; i++) {
            pthread_t tid;
            if (spawn_detached_worker(&tid, core_thread_pool_worker, q) == 0) {
                actually_spawned++;
            } else {
                write_log_error("[SCALING] pthread_create failed while upscaling");
            }
        }

        // Jika ada pthread_create yang gagal, kembalikan reservasi slotnya
        if (actually_spawned < spawn_count) {
            pthread_mutex_lock(&q->lock);
            q->total_workers -= (spawn_count - actually_spawned);
            pthread_mutex_unlock(&q->lock);
        }

        write_log("[SCALING] Load spike detected. Upscaling pool to %d workers (%d spawned)", 
                  q->total_workers, actually_spawned);

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

    while (q->head == NULL) {
        if (!q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond); // Beritahu bahwa thread ini keluar
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        gettimeofday(&now, NULL);

        int current_timeout = get_adaptive_timeout(q); 
        ts.tv_sec = now.tv_sec + current_timeout;
        ts.tv_nsec = now.tv_usec * 1000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        
        if (!q->is_running) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        // === LOGIKA DOWNSCALING (DETACHED WORKER) ===
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("[SCALING] Load subsided. Downscaling pool to %d workers", q->total_workers);
            pthread_cond_signal(&q->exit_cond); // Beritahu bahwa thread ini keluar
            pthread_mutex_unlock(&q->lock);
            
            return -3; // Thread langsung exit secara mandiri, OS mendaur ulang memorinya karena detached
        }
    }

    if (!q->is_running) {
        q->total_workers--;
        pthread_cond_signal(&q->exit_cond);
        pthread_mutex_unlock(&q->lock);
        return -3;
    }

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
    
    pthread_mutex_unlock(&q->lock);
    free(tmp);
    
    return sock;
}

/********************************************************************
 * queue_thread_worker_stop()
 * Shutdown bersih menggunakan exit_cond tanpa pthread_join/SIGUSR1
 ********************************************************************/
void core_queue_thread_worker_stop(void) {
    pthread_mutex_lock(&global_queue.lock);
    global_queue.is_running = 0; 
    pthread_cond_broadcast(&global_queue.cond); // Bangunkan semua thread yang tidur

    // Tunggu sampai seluruh worker thread benar-benar keluar (total_workers == 0)
    while (global_queue.total_workers > 0) {
        pthread_cond_wait(&global_queue.exit_cond, &global_queue.lock);
    }
    pthread_mutex_unlock(&global_queue.lock);

    // Bersihkan sisa task di dalam antrean
    pthread_mutex_lock(&global_queue.lock);
    Task *curr = global_queue.head;
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    pthread_mutex_unlock(&global_queue.lock);

    while (curr) {
        Task *tmp = curr;
        curr = curr->next;
        if (tmp->event.fd >= 0) {
            // Menggunakan core_conn_deactivate sesuai nama asli modul connection
            core_conn_t_deactivate(tmp->event.fd);
            close(tmp->event.fd);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond);
    pthread_cond_destroy(&global_queue.exit_cond);

    write_log("[QUEUE] Worker thread pool shutdown instantly & cleanly.");
}

/* Helper / Private Function*/
void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size) {
    q->head = q->tail = NULL;
    q->count = 0;
    q->max_queue_limit = max_queue_size; 
    q->active_workers = 0;
    q->total_workers = min_limit;
    q->min_threads_limit = min_limit;
    q->max_threads_limit = max_limit;
    q->scaling_in_progress = 0;
    q->is_running = 1; 
    
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    pthread_cond_init(&q->exit_cond, NULL);
}

// Helper internal untuk membuat thread dengan atribut DETACHED secara aman
int spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    int ret = pthread_create(out_tid, &attr, routine, arg);
    pthread_attr_destroy(&attr);
    return ret;
}

int get_adaptive_timeout(TaskQueue *q) {
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores < 1) n_cores = 1; 

    int high_load_threshold = (int)(n_cores * 2);
    float load_factor = (q->max_queue_limit > 0) ? (float)q->count / q->max_queue_limit : 0;

    if (load_factor > 0.5 || q->count > high_load_threshold) {
        return 300; 
    } 
    else if (q->count > 0) {
        return 60; 
    } 
    else {
        return 30; 
    }
}