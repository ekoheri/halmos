#include "halmos_core_thread_pool.h"
#include "halmos_global.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_conn_table.h"
#include "halmos_http_bridge.h"
#include "halmos_log.h"
 
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
 
void mark_worker_idle(TaskQueue *q);
 
/********************************************************************
 * halmos_worker_routine() -> [SIKLUS KERJA KOKI]
 * Persis Logika Boss: Ambil -> Masak -> Beresin Meja
 ********************************************************************/
void *core_thread_pool_worker(void *arg) {
    (void)arg;
    
    while (1) {
        struct timeval arrival;
        halmos_event_t event_item;
        
        // 1. Ambil tugas (halmos_event_t) dari antrean
        int sock_client = core_queue_pop(&global_queue, &event_item, &arrival);
        
        // Ret -3: Shutdown sequence -> Exit thread secara elegan.
        if (sock_client < 0) {
            break; 
        }    
 
        // === AMBIL POINTER KONEKSI ===
        halmos_conn_t *conn = core_conn_t_get(event_item.fd);
 
        // Mencegah Race Condition jika socket sudah di-close / di-recycle 
        if (!conn || !core_conn_t_is_valid(event_item.fd, event_item.generation)) {
            write_log("[WORKER] Stale event detected on FD %d (Gen: %u). Dropping task.", 
                      event_item.fd, event_item.generation);
            mark_worker_idle(&global_queue);
            continue;
        }
 
        // --- AKUISISI KUNCI KONEKSI ---
        // Mengunci koneksi agar Event Loop tidak dapat memanggil 
        // core_event_loop_cleanup_connection (yang akan membebaskan SSL & close fd)
        // selama worker sedang memproses I/O pada koneksi ini.
        core_conn_t_lock(conn);
 
        // Validasi ulang setelah mendapatkan kunci (double-checked locking pattern)
        // Karena bisa saja Event Loop melakukan cleanup TEPAT SEBELUM worker berhasil mendapat kunci.
        if (!core_conn_t_is_valid(event_item.fd, event_item.generation)) {
            core_conn_t_unlock(conn);
            mark_worker_idle(&global_queue);
            continue;
        }
 
        // 2. PROSES REQUEST (Dispatcher Utama)
        // Sepanjang fungsi ini, I/O terproteksi oleh conn->io_lock
        int status = http_bridge_dispatch(sock_client, event_item.events);

        if (status == 1) {
            // Status 1: Keep-Alive atau SSL Handshake butuh data lagi (EAGAIN)
            // Rearm harus dilakukan SAAT MASIH TERKUNCI agar tidak berlomba dengan cleanup.

            core_event_loop_rearm_epoll_ex(sock_client, EPOLLIN);
            core_conn_t_unlock(conn); // Lepaskan kunci setelah selesai mengatur state
        } else if (status == 2) {
            // Status 2: Butuh BACA lagi saja
            core_event_loop_rearm_epoll_ex(sock_client, EPOLLIN);
            core_conn_t_unlock(conn);
        } else if (status == 3) {
             // Status 3: Butuh TULIS lagi saja
            core_event_loop_rearm_epoll_ex(sock_client, EPOLLOUT);
            core_conn_t_unlock(conn);
        } else if (status == 4) {
            // --- Status 4 : untuk HTTP/2 digunakan untuk file streaning/write backlog
            core_event_loop_rearm_epoll_ex(sock_client, EPOLLIN | EPOLLOUT);
            core_conn_t_unlock(conn);
        } else {
            // Status 0 atau -1: Koneksi selesai atau Error
            // Lepaskan kunci TERLEBIH DAHULU, biarkan fungsi cleanup yang mengakuisisi kunci 
            // agar tidak terjadi deadlock saat cleanup mencoba mengunci ulang.
            core_conn_t_unlock(conn);
            core_event_loop_cleanup_connection(sock_client);
        }
 
        // 4. Tandai koki (thread) kembali IDLE
        mark_worker_idle(&global_queue);
    }
    return NULL;
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
    //pthread_mutex_lock(&q->lock);
    //q->active_workers--;
    //pthread_mutex_unlock(&q->lock);
    atomic_fetch_sub(&q->active_workers, 1);
}
