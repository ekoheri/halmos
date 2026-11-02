#ifndef HALMOS_FCGI_QUEUE_H
#define HALMOS_FCGI_QUEUE_H

#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include "halmos_fcgi_session.h" // Tetap di-include untuk mengambil fungsi pool & slot

// --- 1. TIPE TUGAS (TASK TYPE) ---
typedef enum {
    FCGI_TASK_PROCESS_READ = 1, // Data dari PHP-FPM siap dibaca/diproses oleh worker
    FCGI_TASK_DISCONNECT        // Sesi terputus atau perlu cleanup paksa
} FCGI_TaskType;

// --- 2. STRUKTUR SIMPUL TASK (RINGAN ALA CORE QUEUE) ---
typedef struct FCGI_Task {
    FCGI_TaskType type;             // Jenis tugas yang harus dikerjakan worker
    int session_id;                 // Cukup bawa ID / Indeks Global Pool (menggantikan pointer session)
    struct timeval arrival_time;    // Waktu tugas masuk antrean
    struct FCGI_Task *next;         // Pointer ke task berikutnya
} FCGI_Task;

// --- 3. STRUKTUR TASK QUEUE ---
typedef struct {
    FCGI_Task *head;
    FCGI_Task *tail;
    int size;
    int max_queue_limit;
    
    int min_threads_limit;
    int max_threads_limit;
    int total_workers;
    atomic_int active_workers;
    int scaling_in_progress;
    int is_running;

    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t exit_cond;
} FCGI_TaskQueue;

extern FCGI_TaskQueue global_fcgi_queue;

bool fcgi_queue_start(void);
void fcgi_queue_stop(void);
bool fcgi_queue_push(int session_id, FCGI_TaskType type); // Parameter diubah dari pointer ke int session_id
FCGI_Task* fcgi_queue_pop(struct timeval *arrival);

#endif // HALMOS_FCGI_QUEUE_H