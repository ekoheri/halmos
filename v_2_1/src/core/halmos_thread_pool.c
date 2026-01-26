#include "halmos_thread_pool.h"
#include "halmos_global.h"
// #include "halmos_queue.h"
#include "halmos_http_bridge.h" // Departemen HTTP/1 milik Boss
#include "halmos_log.h"

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>


int epoll_fd;

TaskQueue global_queue;

void mark_worker_idle(TaskQueue *q);
/********************************************************************
 * halmos_worker_routine() -> [SIKLUS KERJA KOKI]
 * Persis Logika Boss: Ambil -> Masak -> Beresin Meja
 ********************************************************************/
void *worker_thread_pool(void *arg){
    (void)arg;
    while (1) {
        struct timeval arrival;
        
        // 1. Ambil tugas dari antrean (Block di sini jika kosong)
        // Dequeue sudah menangani pthread_cond_wait internal
        int sock_client = dequeue(&global_queue, &arrival);

        if (sock_client < 0) continue; // Pastikan socket valid

        // 2. Proses Request (Bisa HTML atau PHP)

        // Panggil bridge_dispatch dari http_bridge 
        // dan cek kembaliannya
        if (bridge_dispatch(sock_client) == 1) {
            // Jika Keep-Alive: Re-arm EPOLL
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLONESHOT;
            ev.data.fd = sock_client;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock_client, &ev) == -1) {
                close(sock_client);
            }
        } else {
            /*
            PAKSA SHUTDOWN SEBELUM CLOSE Ini kunci biar ab nggak timeout!
            Gara-gara lupa gak shutdown, apacche bechmark (ab) jadi ngadat!

            Kenapa shutdown itu Penting?
            Kalau lo cuma pakai close(), kamu cuma nutup pintu 
            dari sisi lo, tapi kernel nggak selalu langsung kirim paket FIN (selesai) 
            ke arah ab atau browser kalau masih ada data di buffer.
            */
            shutdown(sock_client, SHUT_WR); 
            
            // Buang sisa data junk dari client kalau ada
            char junk[1024];
            while(recv(sock_client, junk, sizeof(junk), MSG_DONTWAIT) > 0);

            // 3. Langsung tutup
            close(sock_client);
        }

        // 3. Selesai proses, tandai thread kembali IDLE
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
    pthread_mutex_lock(&q->lock);
    q->active_workers--;
    pthread_mutex_unlock(&q->lock);
}