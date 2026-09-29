#ifndef HALMOS_CORE_QUEUE_H
#define HALMOS_CORE_QUEUE_H

#include "halmos_core_conn_table.h"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

// --- STRUKTUR DATA ---
typedef struct Task {
    halmos_event_t event;
    struct timeval arrival_time;
    struct Task* next;
} Task;

typedef struct {
    Task *head, *tail;
    int count;                      // Jumlah request dalam antrean
    int max_queue_limit;            // Batas maksimal antrean (Tambahkan ini)
    int cpu_cores;                  // Jumlah core CPU (Tambahkan ini)
    _Atomic int active_workers;     // Thread yang sedang sibuk (Busy/Blocked)
    int total_workers;              // Total thread yang tercipta saat ini

    int scaling_in_progress;

    int is_running;
    
    // Variabel thread dinamis
    int min_threads_limit;
    int max_threads_limit;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t exit_cond;
} TaskQueue;

// --- PROTOTIPE FUNGSI ---

void core_queue_thread_worker_start(void);
int core_queue_push(TaskQueue *q, halmos_event_t event_item);
int core_queue_pop(TaskQueue *q, halmos_event_t *out_event, struct timeval *arrival);
void core_queue_thread_worker_stop(void);

#endif