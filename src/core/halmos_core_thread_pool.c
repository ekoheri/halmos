#include "halmos_core_thread_pool.h"
#include "halmos_global.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_connection.h"
#include "halmos_http_bridge.h"
#include "halmos_log.h"
 
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
 
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
        int sock_client = queue_pop(&global_queue, &event_item, &arrival);
        
        // Ret -3: Shutdown sequence -> Exit thread secara elegan.
        if (sock_client < 0) {
            break; 
        }    
 
        // === AMBIL POINTER KONEKSI ===
        halmos_conn_t *conn = core_conn_get(event_item.fd);
 
        // === VALIDASI KRITIS STALE CONNECTION (GENERATION CHECK) ===
        // Mencegah Race Condition jika socket sudah di-close / di-recycle 
        if (!conn || !core_conn_is_valid(event_item.fd, event_item.generation)) {
            write_log("[WORKER] Stale event detected on FD %d (Gen: %u). Dropping task.", 
                      event_item.fd, event_item.generation);
            mark_worker_idle(&global_queue);
            continue;
        }
 
        // --- AKUISISI KUNCI KONEKSI ---
        // Mengunci koneksi agar Event Loop tidak dapat memanggil 
        // event_loop_cleanup_connection (yang akan membebaskan SSL & close fd)
        // selama worker sedang memproses I/O pada koneksi ini.
        core_conn_lock(conn);
 
        // Validasi ulang setelah mendapatkan kunci (double-checked locking pattern)
        // Karena bisa saja Event Loop melakukan cleanup TEPAT SEBELUM worker berhasil mendapat kunci.
        if (!core_conn_is_valid(event_item.fd, event_item.generation)) {
            core_conn_unlock(conn);
            mark_worker_idle(&global_queue);
            continue;
        }
 
        // Catat statistik global
        atomic_fetch_add(&global_telemetry.total_requests, 1);
 
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
 
        // 2. PROSES REQUEST (Dispatcher Utama)
        // Sepanjang fungsi ini, I/O terproteksi oleh conn->io_lock
        int status = http_bridge_dispatch(sock_client, event_item.events);
 
        // --- DEBUG TRACE ---
        //fprintf(stderr, "[DEBUG-WORKER] FD: %d | Events: 0x%X | Dispatch Status: %d\n", 
        //        sock_client, event_item.events, status);
        //fflush(stderr);

        // 3. EVALUASI HASIL DISPATCH
        // Status 1 (generik EPOLLIN|EPOLLOUT) dipertahankan apa adanya untuk
        // http1_manager_session/http2_manager_session. Status 2/3 datang dari
        // titik-titik di bridge (peek TLS, SSL_accept handshake, protocol
        // retry) yang butuh rearm spesifik supaya tidak busy-loop di
        // edge-triggered epoll.
        if (status == 1) {
            // Status 1: Keep-Alive atau SSL Handshake butuh data lagi (EAGAIN)
            // Rearm harus dilakukan SAAT MASIH TERKUNCI agar tidak berlomba dengan cleanup.
            // fprintf(stderr, "[DEBUG-WORKER] FD: %d -> Status 1 (Keep-Alive/Selesai). Rearm EPOLLIN\n", sock_client);

            //event_loop_rearm_epoll(sock_client);
            event_loop_rearm_epoll_ex(sock_client, EPOLLIN);
            core_conn_unlock(conn); // Lepaskan kunci setelah selesai mengatur state
        } else if (status == 2) {
            // Status 2: Butuh BACA lagi saja
            // fprintf(stderr, "[DEBUG-WORKER] FD: %d -> Status 2 (WANT_READ). Rearm EPOLLIN\n", sock_client);
            event_loop_rearm_epoll_ex(sock_client, EPOLLIN);
            core_conn_unlock(conn);
        } else if (status == 3) {
            // fprintf(stderr, "[DEBUG-WORKER] FD: %d -> Status 3 (WANT_WRITE). Rearm EPOLLOUT\n", sock_client);
            // Status 3: Butuh TULIS lagi saja
            event_loop_rearm_epoll_ex(sock_client, EPOLLOUT);
            core_conn_unlock(conn);
        } else if (status == 4) {
            // --- TAMBAHAN UNTUK HTTP/2 FILE STREAMING / WRITE BACKLOG ---
            // fprintf(stderr, "[DEBUG-WORKER] FD: %d -> Status 4 (WANT_WRITE). Rearm EPOLLIN | EPOLLOUT\n", sock_client);
            event_loop_rearm_epoll_ex(sock_client, EPOLLIN | EPOLLOUT);
            core_conn_unlock(conn);
        } else {
            // fprintf(stderr, "[DEBUG-WORKER] FD: %d -> Status %d (Close/Error). Cleaning up...\n", sock_client, status);
            // Status 0 atau -1: Koneksi selesai atau Error
            // Lepaskan kunci TERLEBIH DAHULU, biarkan fungsi cleanup yang mengakuisisi kunci 
            // agar tidak terjadi deadlock saat cleanup mencoba mengunci ulang.
            core_conn_unlock(conn);
            
            atomic_fetch_sub(&global_telemetry.active_connections, 1);
            event_loop_cleanup_connection(sock_client);
        }
 
        // --- TELEMETRY & LOGGING ---
        clock_gettime(CLOCK_MONOTONIC, &end);
        atomic_store(&global_telemetry.last_latency_ms, hitung_durasi(start, end));
        
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
