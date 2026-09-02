#ifndef HALMOS_CORE_QUEUE_H
#define HALMOS_CORE_QUEUE_H

#include "halmos_core_connection.h"

#include <pthread.h>
#include <sys/time.h>

// --- KONFIGURASI DYNAMIC CONTROL ---

#define MAX_QUEUE_SIZE 5000 // Batas antrean untuk mencegah memory overflow (Production Scale)

// --- STRUKTUR DATA ---
typedef struct Task {
    halmos_event_t event;
    struct timeval arrival_time;
    struct Task* next;
} Task;

typedef struct {
    Task *head, *tail;
    int count;              // Jumlah request dalam antrean
    int max_queue_limit;    // Batas maksimal antrean (Tambahkan ini)
    int cpu_cores;          // Jumlah core CPU (Tambahkan ini)
    int active_workers;     // Thread yang sedang sibuk (Busy/Blocked)
    int total_workers;      // Total thread yang tercipta saat ini

    int is_running;
    
    // Tambahkan variabel ini agar dinamis
    int min_threads_limit;
    int max_threads_limit;

    pthread_mutex_t lock;
    pthread_cond_t cond;
} TaskQueue;

// --- PROTOTIPE FUNGSI ---

void queue_thread_worker_start(void);
// Signature disesuaikan dengan halmos_event_t
int queue_push(TaskQueue *q, halmos_event_t event_item);
int queue_pop(TaskQueue *q, halmos_event_t *out_event, struct timeval *arrival);
void queue_thread_worker_stop(void);
//void mark_worker_idle(TaskQueue *q);

#endif