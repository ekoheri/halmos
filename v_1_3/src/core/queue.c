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

/********************************************************************
 * init_queue()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti pertama kali membuka dapur restoran.
 *
 * - Menyiapkan meja antre kosong
 * - Menentukan jumlah koki minimal & maksimal
 * - Menyiapkan kunci pintu dapur (mutex)
 * - Menyiapkan bel panggil koki (condition variable)
 *
 * Ibarat:
 * "Oke, dapur siap beroperasi, belum ada pesanan."
 ********************************************************************/
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

/********************************************************************
 * enqueue()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini adalah tugas RESEPSIONIS memasukkan pesanan ke dapur.
 *
 * Alurnya seperti ini:
 * 1. Cek dulu meja antre penuh nggak?
 *    → Kalau penuh, tamu ditolak (return -1)
 *
 * 2. Kalau masih muat:
 *    → resepsionis menulis nota pesanan baru
 *      (malloc Task)
 *
 * 3. Nota ditempel di belakang antrean
 *
 * 4. Kalau koki kewalahan:
 *    → manajer nambah koki baru (upscaling)
 *
 * 5. Bel dipencet → koki dibangunkan
 ********************************************************************/
int enqueue(TaskQueue *q, int sock) { 
    pthread_mutex_lock(&q->lock);
    
    // 1. Cek dulu meja antre penuh nggak?
    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        return -1; // Tanda antrean penuh
    }
    pthread_mutex_unlock(&q->lock);

    // 2. Kalau masih muat:
    Task *new_task = malloc(sizeof(Task));
    if (!new_task) return -2; // Error RAM penuh

    new_task->client_sock = sock;
    gettimeofday(&new_task->arrival_time, NULL);
    new_task->next = NULL;

    pthread_mutex_lock(&q->lock);
    
    // 3. Masukkan ke antrean (Nota ditempel di belakang antrean)
    if (q->tail == NULL) {
        q->head = q->tail = new_task;
    } else {
        q->tail->next = new_task;
        q->tail = new_task;
    }
    q->count++;

    // 4. LOGIKA UPSCALING DINAMIS
    // manajer nambah koki baru (upscaling)
    if (q->count > 0 && q->active_workers >= q->total_workers && q->total_workers < q->max_threads_limit) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, worker_routine, q) == 0) {
            pthread_detach(tid); 
            q->total_workers++;
            write_log("Dynamic Scaling: UPSCALING! Total Workers: %d", q->total_workers);
        }
    }

    // 5. Bel dipencet → koki dibangunkan
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0; // Sukses
}

/********************************************************************
 * get_adaptive_timeout()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti aturan:
 * "Berapa lama koki boleh nganggur sebelum disuruh pulang?"
 *
 * - Kalau restoran lagi rame:
 *     → koki disuruh stay lama (60 detik)
 *
 * - Kalau sedang normal:
 *     → tunggu 30 detik
 *
 * - Kalau sepi banget:
 *     → 10 detik langsung pulang
 *
 * Keputusan dilihat dari:
 * - Panjang antrean
 * - Jumlah core CPU (kapasitas dapur)
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
    
    // 4. Kalau restoran lagi rame:koki disuruh stay lama (60 detik)
    if (load_factor > 0.5 || q->count > high_load_threshold) {
        return 60; 
    } 
    
    // 5. Kalau sedang normal:tunggu 30 detik
    else if (q->count > 0) {
        return 30; 
    } 
    
    // 6. Kalau sepi banget:10 detik langsung pulang
    else {
        return 10; 
    }
}

/********************************************************************
 * dequeue()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini adalah KOKI mengambil nota dari meja antre.
 *
 * - Kalau belum ada pesanan:
 *     koki tidur sambil nunggu bel.
 *
 * - Kalau kelamaan sepi:
 *     koki dipulangkan (downscaling).
 *
 * - Kalau ada pesanan:
 *     nota diambil,
 *     status koki jadi "lagi masak"
 ********************************************************************/
int dequeue(TaskQueue *q, struct timeval *arrival) {
    //1. Kalau belum ada pesanan: koki tidur sambil nunggu bel.
    pthread_mutex_lock(&q->lock);
    
    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        gettimeofday(&now, NULL);

        int current_timeout = get_adaptive_timeout(q); 
        ts.tv_sec = now.tv_sec + current_timeout;
        // -------------------------
        ts.tv_nsec = now.tv_usec * 1000;

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        
        // 2. Kalau timeout dan koki kebanyakan → istirahatkan (downscaling)
        if (rc == ETIMEDOUT && q->total_workers > q->min_threads_limit) {
            q->total_workers--;
            write_log("Dynamic Scaling: DOWNSCALING! Thread terminated due to timeout. Remaining: %d", 
                q->total_workers);
            pthread_mutex_unlock(&q->lock);
            pthread_exit(NULL); 
        }
    }

    // 3. Kalau masih ada pesanan, ambil nota paling depan
    Task *tmp = q->head;
    int sock = tmp->client_sock;
    *arrival = tmp->arrival_time;
    
    q->head = q->head->next;
    if (q->head == NULL) q->tail = NULL;
    q->count--;

    // 4. Koki sekarang statusnya sibuk
    q->active_workers++; 
    pthread_mutex_unlock(&q->lock);
    free(tmp);
    return sock;
}

/********************************************************************
 * mark_worker_idle()
 * ---------------------------------------------------------------
 * Analogi:
 * Setelah koki selesai masak:
 *
 * Dia laporan ke manajer:
 * "Saya sudah selesai, siap terima pesanan lagi."
 *
 * Status active_workers dikurangi satu.
 ********************************************************************/
void mark_worker_idle(TaskQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->active_workers--;
    pthread_mutex_unlock(&q->lock);
}