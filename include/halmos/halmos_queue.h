#ifndef HALMOS_QUEUE_H
#define HALMOS_QUEUE_H

#include <pthread.h>
#include <sys/time.h>

// --- KONFIGURASI DYNAMIC CONTROL ---

#define MAX_QUEUE_SIZE 5000 // Batas antrean untuk mencegah memory overflow (Production Scale)

// --- STRUKTUR DATA ---
typedef struct Task {
    int client_sock;
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
    
    // Tambahkan variabel ini agar dinamis
    int min_threads_limit;
    int max_threads_limit;

    pthread_mutex_t lock;
    pthread_cond_t cond;
} TaskQueue;

// --- PROTOTIPE FUNGSI ---
//void *worker_thread_pool(void *arg);
//void init_queue(TaskQueue *q, int min_limit, int max_limit);
void start_thread_worker();
int enqueue(TaskQueue *q, int sock);
int dequeue(TaskQueue *q, struct timeval *arrival);
//void mark_worker_idle(TaskQueue *q);

#endif