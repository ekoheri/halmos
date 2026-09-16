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

// === PERBAIKAN: Lock khusus untuk worker_threads[] & active_worker_count ===
// Dipisah dari q->lock supaya penulisan bookkeeping array thread (yang sekarang
// terjadi DI LUAR q->lock, lihat queue_push) tidak balapan antar pemanggil,
// tanpa ikut menahan lock hot-path yang dipakai tiap push/pop task.
static pthread_mutex_t worker_registry_lock = PTHREAD_MUTEX_INITIALIZER;

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
    // === PERBAIKAN: pthread_create() TIDAK LAGI dipanggil di dalam q->lock ===
    // Sebelumnya, syscall mahal ini dijalankan sambil memegang lock yang sama
    // dipakai oleh queue_push() & queue_pop() di semua thread -> jadi bottleneck
    // tunggal saat concurrency tinggi (event loop & semua worker ikut ter-block).
    //
    // Strategi: "reserve" slot total_workers DI DALAM lock (murah, atomic secara
    // logis terhadap thread lain), lalu pthread_create() dipanggil SETELAH lock
    // dilepas. scaling_in_progress mencegah beberapa push berturut-turut memicu
    // spawn ganda untuk lonjakan beban yang sama.

    int queue_threshold = q->max_queue_limit * 0.3; // Ambang batas 30%
    int spawn_count = 0;

    if (q->count > queue_threshold 
        && q->total_workers < q->max_threads_limit 
        && !q->scaling_in_progress) {

        int available_slots = q->max_threads_limit - q->total_workers;
        spawn_count = (available_slots < 4) ? available_slots : 4;

        // Reserve dulu slotnya supaya push lain yang datang bersamaan
        // tidak ikut memicu spawn untuk beban yang sama.
        q->total_workers += spawn_count;
        q->scaling_in_progress = 1;
    }

    // 5. Bangunkan koki yang lagi tidur
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);

    // === Spawn thread SETELAH lock dilepas ===
    if (spawn_count > 0) {
        int actually_spawned = 0;

        for (int i = 0; i < spawn_count; i++) {
            pthread_t tid;
            if (pthread_create(&tid, NULL, core_thread_pool_worker, q) == 0) {
                actually_spawned++;

                // PERBAIKAN: worker_threads[] diakses dari banyak thread pemanggil
                // queue_push() secara paralel -> perlu lock terpisah (ringan,
                // bukan q->lock) supaya penulisan index tidak saling tabrakan.
                pthread_mutex_lock(&worker_registry_lock);
                if (worker_threads && active_worker_count < g_worker_max) {
                    worker_threads[active_worker_count++] = tid;
                }
                pthread_mutex_unlock(&worker_registry_lock);
            } else {
                write_log_error("[SCALING] pthread_create failed while upscaling");
            }
        }

        // Jika ada yang gagal dibuat, kembalikan reservasi yang tidak terpakai
        // supaya total_workers tetap merepresentasikan jumlah thread yang benar-benar hidup.
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

    //q->active_workers++;
    atomic_fetch_add(&q->active_workers, 1); 
    
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

    // Kunci registry saat shutdown untuk memastikan tidak ada penulisan
    // worker_threads[] yang masih berlangsung dari queue_push() sisa upscaling.
    pthread_mutex_lock(&worker_registry_lock);
    pthread_t *threads_snapshot = worker_threads;
    int count_snapshot = active_worker_count;
    worker_threads = NULL; // Cegah penulisan baru setelah ini
    pthread_mutex_unlock(&worker_registry_lock);

    if (threads_snapshot != NULL) {
        for (int i = 0; i < count_snapshot; i++) {
            pthread_kill(threads_snapshot[i], SIGUSR1);
        }

        for (int i = 0; i < count_snapshot; i++) {
            pthread_join(threads_snapshot[i], NULL);
        }

        free(threads_snapshot);
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
            core_conn_t_deactivate(tmp->event.fd);
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
    q->scaling_in_progress = 0;

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