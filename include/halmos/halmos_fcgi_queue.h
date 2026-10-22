#ifndef HALMOS_FCGI_QUEUE_H
#define HALMOS_FCGI_QUEUE_H

#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include "halmos_fcgi_session.h" // Menggunakan struktur sesi FSM

// --- 1. TIPE TUGAS (TASK TYPE) ---
typedef enum {
    FCGI_TASK_PROCESS_READ = 1, // Data dari PHP-FPM siap dibaca/diproses oleh worker
    FCGI_TASK_DISCONNECT        // Sesi terputus atau perlu cleanup paksa
} FCGI_TaskType;

// --- 2. STRUKTUR SIMPUL TASK ---
typedef struct FCGITask {
    FCGI_TaskType type;         // Jenis tugas yang harus dikerjakan worker
    HalmosFCGISession *session; // Pointer ke sesi FSM terkait
    struct timeval arrival_time;// Waktu tugas masuk antrean (untuk metrik/wait time)
    struct FCGITask *next;      // Pointer ke task berikutnya dalam linked list
} FCGITask;

// --- 3. STRUKTUR TASK QUEUE (ADAPTIVE & THREAD-SAFE) ---
typedef struct {
    FCGITask *head;             // Elemen pertama dalam antrean
    FCGITask *tail;             // Elemen terakhir dalam antrean
    int size;                   // Jumlah total task yang sedang mengantre (menggantikan count)
    int max_queue_limit;        // Batas kapasitas maksimal antrean
    
    // Variabel Adaptive Worker Pool (Meniru Core Queue)
    int min_threads_limit;
    int max_threads_limit;
    int total_workers;
    atomic_int active_workers;
    int scaling_in_progress;
    int is_running;

    pthread_mutex_t lock;       // Mutex pengaman akses konkuren
    pthread_cond_t not_empty;   // Condition variable untuk worker tidur/bangun
    pthread_cond_t exit_cond;   // Condition variable untuk sinkronisasi shutdown
} FCGITaskQueue;

// Deklarasi variabel global queue (jika diperlukan secara global seperti di core)
extern FCGITaskQueue global_fcgi_queue;

// --- 4. PROTOTIPE FUNGSI INTERFACE ---

/**
 * Menginisialisasi global task queue dengan batas min/max worker dan kapasitas antrean.
 */
bool halmos_fcgi_queue_init(int min_limit, int max_limit, int max_queue_size);

/**
 * Menghancurkan antrean dan membersihkan seluruh memori task yang tersisa secara elegan.
 */
void halmos_fcgi_queue_destroy(void);

/**
 * Memasukkan task baru ke dalam antrean (Enqueue) secara thread-safe.
 * Dilengkapi dengan logika UPSCALING jika antrean melebihi ambang batas.
 */
bool halmos_fcgi_queue_push(HalmosFCGISession *session, FCGI_TaskType type);

/**
 * Mengambil task dari antrean (Dequeue) secara thread-safe dengan timeout adaptif.
 * Dilengkapi dengan logika DOWNSCALING (terminasi mandiri detached worker jika idle).
 * 
 * @return Pointer ke FCGITask yang harus dieksekusi, atau NULL jika worker harus keluar.
 */
FCGITask* halmos_fcgi_queue_pop(struct timeval *arrival);

void halmos_fcgi_queue_broadcast(void);

#endif // HALMOS_FCGI_QUEUE_H