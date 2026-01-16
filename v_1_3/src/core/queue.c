#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "../include/core/queue.h"
#include "../include/core/config.h"
#include "../include/core/log.h"

extern Config config;
// Mengambil fungsi worker_routine di web_server.c
extern void *worker_routine(void *arg);

void init_queue(TaskQueue *q, int min_limit, int max_limit) {
    q->head = q->tail = NULL;
    q->count = 0;
    q->max_queue_limit = config.max_queue_size; 
    q->active_workers = 0;
    q->total_workers = min_limit;
    q->min_threads_limit = min_limit;
    q->max_threads_limit = max_limit;
    
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

int enqueue(TaskQueue *q, int sock) { // Ubah return type menjadi int
    pthread_mutex_lock(&q->lock);
    
    // --- PROTEKSI ANTREAN ---
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        return -1; // Tanda antrean penuh
    }
    pthread_mutex_unlock(&q->lock);

    // Jika belum penuh, baru alokasi memori
    Task *new_task = malloc(sizeof(Task));
    if (!new_task) return -2; // Error RAM penuh

    new_task->client_sock = sock;
    gettimeofday(&new_task->arrival_time, NULL);
    new_task->next = NULL;

    pthread_mutex_lock(&q->lock);
    
    // 1. Masukkan ke antrean (Logika Anda sudah benar)
    if (q->tail == NULL) {
        q->head = q->tail = new_task;
    } else {
        q->tail->next = new_task;
        q->tail = new_task;
    }
    q->count++;

    // 2. LOGIKA UPSCALING DINAMIS (Tetap biarkan seperti milik Anda)
    if (q->count > 0 && q->active_workers >= q->total_workers && q->total_workers < q->max_threads_limit) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, worker_routine, q) == 0) {
            pthread_detach(tid); 
            q->total_workers++;
            write_log("Dynamic Scaling: UPSCALING! Total Workers: %d", q->total_workers);
        }
    }

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0; // Sukses
}

// Fungsi untuk menghitung timeout berdasarkan beban antrean
int get_adaptive_timeout(TaskQueue *q) {
    // 1. Ambil jumlah CPU Core yang aktif secara otomatis
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores < 1) n_cores = 1; // Fallback minimal 1 core

    // 2. Hitung threshold ideal (2x jumlah core)
    int high_load_threshold = (int)(n_cores * 2);

    // 3. Hitung rasio beban antrean (Load Factor)
    float load_factor = (q->max_queue_limit > 0) ? (float)q->count / q->max_queue_limit : 0;

    // --- LOGIKA ADAPTIF ---
    
    // KONDISI A: Sibuk (Antrean terisi > 50% ATAU sudah melampaui kemampuan paralel CPU)
    if (load_factor > 0.5 || q->count > high_load_threshold) {
        return 60; // Tahan thread 1 menit (High Persistence)
    } 
    
    // KONDISI B: Moderat (Ada antrean tapi masih terkendali)
    else if (q->count > 0) {
        return 30; // Tahan thread 30 detik
    } 
    
    // KONDISI C: Idle (Antrean kosong sama sekali)
    else {
        return 10; // Matikan thread dalam 10 detik (Agresif)
    }
}

int dequeue(TaskQueue *q, struct timeval *arrival) {
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        gettimeofday(&now, NULL);

        // --- PERUBAHAN DI SINI ---
        int current_timeout = get_adaptive_timeout(q); 
        ts.tv_sec = now.tv_sec + current_timeout;
        // -------------------------
        ts.tv_nsec = now.tv_usec * 1000;

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        
        // JIKA TIMEOUT DAN JUMLAH THREAD MASIH DI ATAS MINIMUM -> MATIKAN THREAD
        if (rc == ETIMEDOUT && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("Dynamic Scaling: DOWNSCALING! Thread terminated due to timeout. Remaining: %d", 
                q->total_workers);
            pthread_mutex_unlock(&q->lock);
            pthread_exit(NULL); // Thread ini selesai/mati
        }
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

// Fungsi tambahan untuk menandai thread kembali IDLE
void mark_worker_idle(TaskQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->active_workers--;
    pthread_mutex_unlock(&q->lock);
}