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
#include <sys/resource.h> // Untuk rlimit (FD)
#include <sys/sysinfo.h>  // Untuk sysinfo (RAM)
#include <unistd.h>       // Untuk sysconf (CPU Cores)
#include <signal.h>

//Pemilik variable global global_queue
TaskQueue global_queue;

// Pointer ke array pthread_t (dinamis)
static pthread_t *worker_threads = NULL; 
static int active_worker_count = 0;

static void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size);

static int get_adaptive_timeout(TaskQueue *q);

static void sigusr1_handler(int sig) {
    (void)sig; // Mencegah warning unused parameter
}

/*
Algoritma penjadwalan pada Halmos Core mengadopsi pendekatan hibrida 
dengan mengevaluasi batasan logis (File Descriptor) dan 
batasan fisik (Physical RAM) secara simultan. 
Dengan menerapkan prinsip Minimum Resource Bottleneck, 
sistem secara otomatis menentukan kapasitas worker yang optimal 
untuk mencegah kegagalan sistem akibat limitasi kernel maupun saturasi memori, 
sebuah mekanisme yang memberikan stabilitas lebih tinggi dibandingkan 
konfigurasi statis pada server konvensional.
*/
/*void queue_thread_worker_start() {
    // Inisialisasi antrean tugas
    init_queue(&global_queue, g_worker_min, g_worker_max, g_queue_capacity);

    for (int i = 0; i < g_worker_min; i++) { // Bikin sesuai minimal aja
        pthread_t worker_tid;
        pthread_create(&worker_tid, NULL, core_thread_pool_worker, &global_queue);
        pthread_detach(worker_tid);
    }
}*/

void queue_thread_worker_start() {
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Tanpa SA_RESTART agar blocking syscall return EINTR
    sigaction(SIGUSR1, &sa, NULL);
    
    // 1. Inisialisasi struct antrean global agar warning init_queue hilang
    init_queue(&global_queue, g_worker_min, g_worker_max, g_queue_capacity);

    // 2. Alokasikan memori sebesar g_worker_max dari modul adaptive
    active_worker_count = g_worker_max;
    
    worker_threads = calloc(active_worker_count, sizeof(pthread_t));
    if (!worker_threads) {
        write_log_error("[FATAL] Failed to allocate memory for worker threads array.");
        exit(EXIT_FAILURE);
    }

    // 3. Buat worker thread sebanyak g_worker_max
    for (int i = 0; i < active_worker_count; i++) {
        if (pthread_create(&worker_threads[i], NULL, core_thread_pool_worker, &global_queue) != 0) {
            write_log_error("[ERR] Failed to create worker thread %d", i);
        }
    }
    
    write_log("[QUEUE] Thread pool started dynamically with %d workers.", active_worker_count);
}

/********************************************************************
 * enqueue() -> [Resepsionis Enqueue]
 * Logika Upscaling Dinamis milik Boss.
 ********************************************************************/
int queue_push(TaskQueue *q, int sock) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Safety Check: Kapasitas Parkir
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        write_log_error("[QUEUE] Capacity reached! Rejecting client FD %d", sock);
        return -1; 
    }

    // 2. Alokasi Task (Siapkan Nota Pesanan)
    Task *new_task = malloc(sizeof(Task));
    if (!new_task) {
        pthread_mutex_unlock(&q->lock);
        return -2; 
    }

    new_task->client_sock = sock;
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
    /* Strategi: 
       - Jangan tunggu koki habis (active >= total).
       - Jika antrean sudah terisi > 30% DAN koki yang ada tinggal sedikit yang nganggur,
       - Maka tambah koki dalam jumlah BATCH (langsung 4) supaya tidak sering-sering panggil syscall.
    */
    int queue_threshold = q->max_queue_limit * 0.3; // Ambang batas 30%
    
    if (q->count > queue_threshold && q->total_workers < q->max_threads_limit) {
        
        // Spawn koki dalam batch (misal 4 koki sekaligus)
        int spawn_count = 4; 
        for (int i = 0; i < spawn_count; i++) {
            if (q->total_workers < q->max_threads_limit) {
                pthread_t tid;
                if (pthread_create(&tid, NULL, core_thread_pool_worker, q) == 0) {
                    pthread_detach(tid);
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
 * queue_pop() -> [Koki Dequeue]
 * Logika Downscaling & Timedwait milik Boss.
 ********************************************************************/
int queue_pop(TaskQueue *q, struct timeval *arrival) {
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        // [CEK 1] Keluar langsung jika flag shutdown aktif
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
        
        // [CEK 2] WAJIB CEK KEMBALI SEGERA SETELAH BANGUN
        if (!q->is_running) {
            q->total_workers--;
            pthread_mutex_unlock(&q->lock);
            return -3;
        }

        // Logika Downscaling (PERBAIKAN: Gunakan return -3 agar keluar secara seragam lewat worker loop)
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("[SCALING] Load subsided. Downscaling pool to %d workers", q->total_workers);
            pthread_mutex_unlock(&q->lock);
            return -3; // PERBAIKAN: Ganti pthread_exit(NULL) dengan return -3
        }
    }

    // PERBAIKAN VITAL: Walaupun q->head != NULL, JIKA SERVER SEDANG SHUTDOWN, 
    // JANGAN PROSES TASK LAGI! Langsung exit agar worker cepat mati!
    if (!q->is_running) {
        q->total_workers--;
        pthread_mutex_unlock(&q->lock);
        return -3;
    }

    Task *tmp = q->head;
    int sock = tmp->client_sock;
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
 * queue_thread_worker_stop() TANPA ARRAY
 * Melakukan shutdown bersih memanfaatkan counter q->total_workers
 ********************************************************************/
 void queue_thread_worker_stop() {
    // 1. Set flag shutdown & broadcast condition variable
    pthread_mutex_lock(&global_queue.lock);
    global_queue.is_running = 0; 
    pthread_cond_broadcast(&global_queue.cond); 
    pthread_mutex_unlock(&global_queue.lock);

    // 2. UNBLOCK AKTIF: Kirim sinyal interrupt ke setiap worker thread yang ada di array
    if (worker_threads != NULL) {
        for (int i = 0; i < active_worker_count; i++) {
            // Memaksa poll() / read() di worker return EINTR instan
            pthread_kill(worker_threads[i], SIGUSR1);
        }

        // 3. JOIN DETERMINISTIK: Tunggu semua worker keluar rapi
        for (int i = 0; i < active_worker_count; i++) {
            pthread_join(worker_threads[i], NULL);
        }

        // 4. BEBASKAN MEMORI ARRAY
        free(worker_threads);
        worker_threads = NULL;
    }

    // 5. Cleanup sisa antrean Task yang belum diambil
    pthread_mutex_lock(&global_queue.lock);
    Task *curr = global_queue.head;
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    pthread_mutex_unlock(&global_queue.lock);

    while (curr) {
        Task *tmp = curr;
        curr = curr->next;
        if (tmp->client_sock >= 0) {
            close(tmp->client_sock);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond);

    write_log("[QUEUE] Worker thread pool shutdown instantly & cleanly.");
}

/* 
void queue_thread_worker_stop() {
    pthread_mutex_lock(&global_queue.lock);
    global_queue.is_running = 0; 
    pthread_cond_broadcast(&global_queue.cond); 
    pthread_mutex_unlock(&global_queue.lock);

    int wait_attempts = 0;
    const int max_attempts = 500; // Naikkan toleransi ke 3 detik (300 * 10ms)

    while (wait_attempts < max_attempts) {
        pthread_mutex_lock(&global_queue.lock);
        int remaining = global_queue.total_workers;
        // Broadcast ulang di setiap loop agar worker yang baru lepas dari http_bridge_dispatch 
        // langsung melihat is_running = 0 dan keluar
        pthread_cond_broadcast(&global_queue.cond);
        pthread_mutex_unlock(&global_queue.lock);

        if (remaining <= 0) break;

        usleep(10000); // 10ms
        wait_attempts++;
    }

    if (wait_attempts >= max_attempts) {
        write_log_error("[QUEUE] Shutdown cutoff hit (%d workers still active).", global_queue.total_workers);
    }

    // Ambil sisa antrean ke variabel lokal agar cleanup close() dilakukan di luar mutex
    pthread_mutex_lock(&global_queue.lock);
    Task *curr = global_queue.head;
    global_queue.head = global_queue.tail = NULL;
    global_queue.count = 0;
    pthread_mutex_unlock(&global_queue.lock);

    while (curr) {
        Task *tmp = curr;
        curr = curr->next;
        if (tmp->client_sock >= 0) {
            close(tmp->client_sock);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond);

    write_log("[QUEUE] Worker thread pool shutdown cleanly.");
}
*/
/********************************************************************
 * init_queue() -> [Dapur Restoran Halmos]
 * Mengambil logika init_queue milik Boss.
 ********************************************************************/
void init_queue(TaskQueue *q, int min_limit, int max_limit, int max_queue_size) {
    q->head = q->tail = NULL;
    q->count = 0;
    q->max_queue_limit = max_queue_size; 
    q->active_workers = 0;
    q->total_workers = min_limit;
    q->min_threads_limit = min_limit;
    q->max_threads_limit = max_limit;

    q->is_running = 1; // Mark queue aktif
    
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

int get_adaptive_timeout(TaskQueue *q) {
    // 1. Ambil jumlah CPU Core yang aktif secara otomatis
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores < 1) n_cores = 1; // Fallback minimal 1 core

    // 2. Hitung threshold ideal (2x jumlah core)
    int high_load_threshold = (int)(n_cores * 2);

    // 3. Hitung rasio beban antrean (Load Factor)
    float load_factor = (q->max_queue_limit > 0) ? (float)q->count / q->max_queue_limit : 0;

    // --- LOGIKA ADAPTIF ---
    
    // 4. Kalau restoran lagi rame:koki disuruh stay lama (120 detik)
    if (load_factor > 0.5 || q->count > high_load_threshold) {
        return 300; 
    } 
    
    // 5. Kalau sedang normal:tunggu 30 detik
    else if (q->count > 0) {
        return 60; 
    } 
    
    // 6. Kalau sepi banget:10 detik langsung pulang
    else {
        return 30; 
    }
}