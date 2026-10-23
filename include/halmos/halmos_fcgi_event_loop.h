#ifndef HALMOS_FCGI_EVENT_LOOP_H
#define HALMOS_FCGI_EVENT_LOOP_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "halmos_fcgi_session.h" // Menggunakan struktur sesi FSM

// --- STRUKTUR POLLER UPSTREAM ---
typedef struct {
    int epoll_fd;               // File descriptor instance epoll mandiri untuk upstream
    pthread_t event_thread;    // Thread mandiri yang menjalankan epoll_wait loop
    volatile bool running;      // Status kontrol untuk menghentikan poller secara aman (graceful stop)
} FCGI_AsyncEventLoop;

// --- PROTOTIPE FUNGSI INTERFACE ---

/**
 * Menginisialisasi instance epoll upstream dan menjalankan thread poller mandiri.
 * @return true jika berhasil, false jika gagal.
 */
bool fcgi_event_loop_start(void);

/**
 * Rutinitas utama thread poller (dijalankan di dalam pthread_create).
 * Berisi loop epoll_wait non-blocking untuk memantau semua fpm_fd.
 */
void* fcgi_event_loop_run(void *arg);


/**
 * Menghentikan thread poller dan menutup instance epoll dengan aman.
 */
void fcgi_event_loop_stop(void);

/**
 * Mendaftarkan fpm_fd (socket PHP-FPM) baru ke dalam epoll poller upstream.
 * @param fpm_fd File descriptor socket PHP-FPM
 * @param session Pointer ke sesi FSM yang terkait dengan socket ini
 * @param events Masker event awal (misal: EPOLLOUT untuk connect atau EPOLLIN)
 * @return true jika berhasil ditambahkan, false jika gagal.
 */
bool fcgi_event_loop_add(int fpm_fd, FCGI_Session *session, uint32_t events);

/**
 * Mengubah (modify) event pemantauan untuk fpm_fd tertentu (misal dari EPOLLOUT ke EPOLLIN).
 */
bool fcgi_event_loop_mod(int fpm_fd, uint32_t events);

/**
 * Menghapus fpm_fd dari pemantauan epoll upstream sebelum socket ditutup.
 */
bool fcgi_event_loop_del(int fpm_fd);

#endif // HALMOS_FCGI_EVENT_LOOP_H