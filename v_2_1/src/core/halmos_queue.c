#include "halmos_queue.h"
#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_log.h"
#include "halmos_thread_pool.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h> // Untuk rlimit (FD)
#include <sys/sysinfo.h>  // Untuk sysinfo (RAM)
#include <unistd.h>       // Untuk sysconf (CPU Cores)

Config config;

int get_adaptive_timeout(TaskQueue *q);

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
    
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
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
void start_thread_worker() {
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit rl;
    struct sysinfo si;
    
    // --- PILAR 1: Batasan Izin (FD) ---
    int fd_based_max = 1000; // Default aman
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        fd_based_max = (int)(rl.rlim_cur / 10);
    }

    // --- PILAR 2: Batasan Fisik (RAM) ---
    int ram_based_max = 1000;
    if (sysinfo(&si) == 0) {
        int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
        // Gunakan jatah 10% dari RAM bebas (freeram) agar lebih akurat
        ram_based_max = (int)((si.freeram * 0.10) / buf_size);
    }

    // --- EKSEKUSI: Ambil Nilai Terendah (The Bottleneck) ---
    int dynamic_thread_max = (fd_based_max < ram_based_max) ? fd_based_max : ram_based_max;

    // --- GUARDRAIL (Batas Keamanan CPU i3) ---
    if (dynamic_thread_max > 10000) dynamic_thread_max = 10000; // Jangan lebih dari 10k thread
    int dynamic_thread_min = (int)num_cores * 4;

    // --- STRATEGI ANTREAN ADAPTIF ---
    // Kita set ruang tunggu sebesar 50% dari sisa kapasitas izin sistem (FD)
    // Jika ulimit 50.000 dan worker 5.000, maka antrean bisa menampung 
    // sekitar 22.500 permintaan yang sedang menunggu diproses.
    int adaptive_queue_size = (int)((rl.rlim_cur - dynamic_thread_max) * 0.5);

    // Guardrail: Minimal 1000, Maksimal 65535 (Limit standar port TCP)
    if (adaptive_queue_size < 1000) adaptive_queue_size = 1000;
    if (adaptive_queue_size > 65535) adaptive_queue_size = 65535;

        // Inisialisasi antrean tugas
    init_queue(&global_queue, dynamic_thread_min, dynamic_thread_max, adaptive_queue_size);

    for (int i = 0; i < dynamic_thread_min; i++) { // Bikin sesuai minimal aja
        pthread_t worker_tid;
        pthread_create(&worker_tid, NULL, worker_thread_pool, &global_queue);
        pthread_detach(worker_tid);
    }


    write_log("Halmos Engine: Adaptive CPU Scaling active.");
    write_log("Cores Detected: %ld. Pool: %d to %d workers. Queue: %d", 
          num_cores, dynamic_thread_min, dynamic_thread_max, adaptive_queue_size);
}

/********************************************************************
 * enqueue() -> [Resepsionis Enqueue]
 * Logika Upscaling Dinamis milik Boss.
 ********************************************************************/
int enqueue(TaskQueue *q, int sock) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Safety Check: Kapasitas Parkir
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        // Tulis log sesekali saja agar tidak banjir log (Throttle logging)
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
                if (pthread_create(&tid, NULL, worker_thread_pool, q) == 0) {
                    pthread_detach(tid);
                    q->total_workers++;
                }
            }
        }
        write_log("[SCALING] High Load Detected! Upscaling to %d workers.", q->total_workers);
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
int dequeue(TaskQueue *q, struct timeval *arrival) {
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    // 1. Loop nunggu pesanan
    while (q->head == NULL) {
        gettimeofday(&now, NULL);

        // Ambil timeout adaptif lu
        int current_timeout = get_adaptive_timeout(q); 
        ts.tv_sec = now.tv_sec + current_timeout;
        ts.tv_nsec = now.tv_usec * 1000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        // Tunggu bel bunyi atau sampai timeout
        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        
        // 2. LOGIKA PERBAIKAN: Cek apakah benar-benar boleh Downscaling
        // Koki hanya boleh keluar jika:
        // - Mengalami timeout (ETIMEDOUT)
        // - Antrean masih kosong (q->head == NULL) -> Ini kunci biar gak mati pas sibuk!
        // - Jumlah koki masih di atas batas minimal
        if (rc == ETIMEDOUT && q->head == NULL && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("[INFO : halmos_queue.c] Dynamic Scaling: DOWNSCALING! Remaining: %d", 
                q->total_workers);
            pthread_mutex_unlock(&q->lock);
            pthread_exit(NULL); 
        }

        // Jika rc == 0 (bel bunyi) tapi q->head masih NULL (spurious wakeup), 
        // while loop akan otomatis mengulang tunggu lagi.
    }

    // 3. Ambil nota (Request) dari antrean
    Task *tmp = q->head;
    int sock = tmp->client_sock;
    *arrival = tmp->arrival_time;
    
    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->count--;

    // 4. Update status koki jadi sibuk
    q->active_workers++; 
    
    pthread_mutex_unlock(&q->lock);
    free(tmp);
    
    return sock;
}

/********************************************************************
 * get_adaptive_timeout() -> [Aturan Nganggur Koki]
 * Logika Adaptive Timeout milik Boss berdasarkan Core CPU.
 ********************************************************************/
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