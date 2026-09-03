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
#include <signal.h>

// Pemilik variabel global global_queue
TaskQueue global_queue;

// Pointer ke array pthread_t (dinamis)
static pthread_t *worker_threads = NULL; 
static int active_worker_count = 0;

static void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size);
static int get_adaptive_timeout(TaskQueue *q);

static void sigusr1_handler(int sig) {
    (void)sig; // Mencegah warning unused parameter
}

void queue_thread_worker_start(void) {
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Tanpa SA_RESTART agar blocking syscall return EINTR
    sigaction(SIGUSR1, &sa, NULL);
    
    // Inisialisasi struct antrean global
    init_queue(&global_queue, g_worker_min, g_worker_max, g_queue_capacity);

    // Alokasikan memori sebesar g_worker_min dari modul adaptive
    active_worker_count = g_worker_min;
    
    worker_threads = calloc(g_worker_max, sizeof(pthread_t)); 
    if (!worker_threads) {
        write_log_error("[FATAL] Failed to allocate memory for worker threads array.");
        exit(EXIT_FAILURE);
    }

    // Buat worker thread sebanyak g_worker_max
    for (int i = 0; i < active_worker_count; i++) {
        if (pthread_create(&worker_threads[i], NULL, core_thread_pool_worker, &global_queue) != 0) {
            write_log_error("[ERR] Failed to create worker thread %d", i);
        }
    }
    
    write_log("[QUEUE] Thread pool started dynamically with %d workers.", active_worker_count);
}

/********************************************************************
 * queue_push()
 * === MODIFIKASI: Menerima halmos_event_t sebagai input ===
 ********************************************************************/
int queue_push(TaskQueue *q, halmos_event_t event_item) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Safety Check: Kapasitas Parkir
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        write_log_error("[QUEUE] Capacity reached! Rejecting client FD %d (Gen: %u)", 
                        event_item.fd, event_item.generation);
        return -1; 
    }

    // 2. Alokasi Task (Siapkan Nota Pesanan)
    Task *new_task = malloc(sizeof(Task));
    if (!new_task) {
        pthread_mutex_unlock(&q->lock);
        return -2; 
    }

    // === MODIFIKASI: Assign struct halmos_event_t ===
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

    // 4. LOGIKA UPSCALING "SMART & ANTISIPATIF"
    int queue_threshold = q->max_queue_limit * 0.3; // Ambang batas 30%
    
    if (q->count > queue_threshold && q->total_workers < q->max_threads_limit) {
        int spawn_count = 4; 
        for (int i = 0; i < spawn_count; i++) {
            if (q->total_workers < q->max_threads_limit) {
                pthread_t tid;
                if (pthread_create(&tid, NULL, core_thread_pool_worker, q) == 0) {
                    // PERBAIKAN: Simpan ke array worker_threads agar aman saat shutdown
                    if (worker_threads && active_worker_count < g_worker_max) {
                        worker_threads[active_worker_count++] = tid;
                    }
                    pthread_detach(tid); // Atau hilangkan detach jika ingin di-join manual saat stop
                    q->total_workers++;
                }
            }
        }
        write_log("[SCALING] Load spike detected. Upscaling pool to %d workers", q->total_workers);
    }

    // 5. Bangunkan koki yang lagi tidur
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    
    return 0;
}

/********************************************************************
 * queue_pop()
 * === MODIFIKASI: Mengekstrak halmos_event_t ke out_event ===
 ********************************************************************/
int queue_pop(TaskQueue *q, halmos_event_t *out_event, struct timeval *arrival) {
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        if (!q->is_running) {
            q->total_workers--;
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
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        // Logika Downscaling
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("[SCALING] Load subsided. Downscaling pool to %d workers", q->total_workers);
            pthread_mutex_unlock(&q->lock);
            return -3; 
        }
    }

    if (!q->is_running) {
        q->total_workers--;
        pthread_mutex_unlock(&q->lock);
        return -3;
    }

    Task *tmp = q->head;
    
    // === MODIFIKASI: Salin struct halmos_event_t ke out_event dan return FD ===
    if (out_event) {
        *out_event = tmp->event;
    }
    int sock = tmp->event.fd;
    *arrival = tmp->arrival_time;
    
    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->count--;

    q->active_workers++; 
    
    pthread_mutex_unlock(&q->lock);
    free(tmp);
    
    return sock;
}

/********************************************************************
 * queue_thread_worker_stop()
 * Cleanup sisa task dan matikan worker threads
 ********************************************************************/
void queue_thread_worker_stop(void) {
    pthread_mutex_lock(&global_queue.lock);
    global_queue.is_running = 0; 
    pthread_cond_broadcast(&global_queue.cond); 
    pthread_mutex_unlock(&global_queue.lock);

    if (worker_threads != NULL) {
        for (int i = 0; i < active_worker_count; i++) {
            pthread_kill(worker_threads[i], SIGUSR1);
        }

        for (int i = 0; i < active_worker_count; i++) {
            pthread_join(worker_threads[i], NULL);
        }

        free(worker_threads);
        worker_threads = NULL;
    }

    pthread_mutex_lock(&global_queue.lock);
    Task *curr = global_queue.head;
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    pthread_mutex_unlock(&global_queue.lock);

    while (curr) {
        Task *tmp = curr;
        curr = curr->next;
        // === MODIFIKASI: Akses client_sock lewat tmp->event.fd ===
        if (tmp->event.fd >= 0) {
            // === MODIFIKASI: Deaktivasi connection state sebelum close ===
            core_conn_deactivate(tmp->event.fd);
            close(tmp->event.fd);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond);

    write_log("[QUEUE] Worker thread pool shutdown instantly & cleanly.");
}

void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size) {
    q->head = q->tail = NULL;
    q->count = 0;
    q->max_queue_limit = max_queue_size; 
    q->active_workers = 0;
    q->total_workers = min_limit;
    q->min_threads_limit = min_limit;
    q->max_threads_limit = max_limit;

    q->is_running = 1; 
    
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
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