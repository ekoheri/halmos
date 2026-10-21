#ifndef HALMOS_FCGI_QUEUE_H
#define HALMOS_FCGI_QUEUE_H

#include <stdbool.h>
#include <pthread.h>
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
    struct FCGITask *next;      // Pointer ke task berikutnya dalam linked list
} FCGITask;

// --- 3. STRUKTUR TASK QUEUE (THREAD-SAFE) ---
typedef struct {
    FCGITask *head;             // Elemen pertama dalam antrean
    FCGITask *tail;             // Elemen terakhir dalam antrean
    int size;                   // Jumlah total task yang sedang mengantre
    pthread_mutex_t lock;       // Mutex pengaman akses konkuren
    pthread_cond_t not_empty;   // Condition variable untuk membangunkan worker yang tidur
} FCGITaskQueue;

// --- 4. PROTOTIPE FUNGSI INTERFACE ---

/**
 * Menginisialisasi global task queue untuk worker pool.
 * @return true jika berhasil, false jika gagal.
 */
bool halmos_fcgi_queue_init(void);

/**
 * Menghancurkan antrean dan membersihkan seluruh memori task yang tersisa.
 */
void halmos_fcgi_queue_destroy(void);

/**
 * Memasukkan task baru ke dalam antrean (Enqueue) secara thread-safe.
 * Dipanggil oleh poller saat epoll mendeteksi event siap (EPOLLIN).
 * Memberikan sinyal (cond_signal) ke worker pool.
 */
bool halmos_fcgi_queue_push(HalmosFCGISession *session, FCGI_TaskType type);

/**
 * Mengambil task dari antrean (Dequeue) secara thread-safe.
 * Dijalankan di dalam loop worker thread. 
 * Akan masuk ke mode sleep (blocking via pthread_cond_wait) jika antrean kosong.
 * @return Pointer ke FCGITask yang harus dieksekusi (harus di-free setelah selesai).
 */
FCGITask* halmos_fcgi_queue_pop(void);

void halmos_fcgi_queue_broadcast(void);

#endif // HALMOS_FCGI_QUEUE_H