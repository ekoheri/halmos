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
typedef struct FCGI_Task {
    FCGI_TaskType type;         // Jenis tugas yang harus dikerjakan worker
    FCGI_Session *session; // Pointer ke sesi FSM terkait
    struct timeval arrival_time;// Waktu tugas masuk antrean (untuk metrik/wait time)
    struct FCGI_Task *next;      // Pointer ke task berikutnya dalam linked list
} FCGI_Task;

// --- 3. STRUKTUR TASK QUEUE (ADAPTIVE & THREAD-SAFE) ---
typedef struct {
    FCGI_Task *head;             // Elemen pertama dalam antrean
    FCGI_Task *tail;             // Elemen terakhir dalam antrean
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
} FCGI_TaskQueue;

// Deklarasi variabel global queue (jika diperlukan secara global seperti di core)
extern FCGI_TaskQueue global_fcgi_queue;


bool fcgi_queue_start(void);

void fcgi_queue_stop(void);

bool fcgi_queue_push(FCGI_Session *session, FCGI_TaskType type);

FCGI_Task* fcgi_queue_pop(struct timeval *arrival);

#endif // HALMOS_FCGI_QUEUE_H