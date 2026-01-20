#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include "event_handler.h"
#include "network_handler.h"
#include "queue.h"
#include "log.h"
#include "http1_response.h"

extern int epoll_fd;
extern int MAX_EVENTS;
extern struct epoll_event *events;

extern TaskQueue global_queue;

void setup_event_system() {
    struct rlimit rl;
    // Cek limit maksimal yang diizinkan kernel
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        write_log("[SYSTEM] Current File Descriptor limits:: Soft=%ld, Hard=%ld\n", (long)rl.rlim_cur, (long)rl.rlim_max);
        
        // Coba set ke limit maksimal yang dibolehkan OS (biasanya 65535 atau lebih)
        rl.rlim_cur = rl.rlim_max; 
        if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
            write_log("[ERROR] Gagal menaikkan ulimit");
        } else {
            write_log("[SYSTEM] Resource limit adjusted: ulimit set to: %ld", (long)rl.rlim_cur);
        }
    }
    // --- LOGIKA ADAPTIVE MAX_EVENTS ---
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        // Ambil 10% dari soft limit sebagai jumlah event yang diproses per batch
        // Contoh: Jika limit 1024, MAX_EVENTS jadi ~102.
        MAX_EVENTS = (int)(rl.rlim_cur / 10);

        // Berikan batasan (Sanity Check) agar tidak terlalu ekstrem
        if (MAX_EVENTS < 64) MAX_EVENTS = 64;      // Minimal 64 agar tetap efisien
        if (MAX_EVENTS > 1024) MAX_EVENTS = 1024;  // Maksimal 1024 agar loop tidak macet
    } else {
        MAX_EVENTS = 64; // Fallback jika getrlimit gagal
    }
    
    events = malloc(sizeof(struct epoll_event) * MAX_EVENTS);
}

/********************************************************************
 * worker_routine()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini adalah KOKI di dapur restoran.
 *
 * - dequeue()  = koki mengambil nota pesanan dari meja antre.
 * - handle_client() = koki memasak sesuai pesanan.
 *
 * Setelah selesai:
 * - Kalau tamu masih mau tambah (keep-alive),
 *   piring dikembalikan ke resepsionis (epoll re-arm).
 * - Kalau selesai makan, meja dibersihkan (close).
 *
 * mark_worker_idle() = koki angkat tangan:
 *   “Saya siap terima order berikutnya!”
 ********************************************************************/
void* worker_routine(void* arg) {
    while (1) {
        struct timeval arrival;
        
        // 1. Ambil tugas dari antrean (Block di sini jika kosong)
        // Dequeue sudah menangani pthread_cond_wait internal
        int sock_client = dequeue(&global_queue, &arrival);

        if (sock_client < 0) continue; // Pastikan socket valid

        // 2. Proses Request (Bisa HTML atau PHP)

        // Panggil handle_client dan cek kembaliannya
        if (handle_client(sock_client) == 1) {
            // Jika Keep-Alive: Re-arm EPOLL
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
            ev.data.fd = sock_client;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock_client, &ev) == -1) {
                close(sock_client);
            }
        } else {
            // Jika Connection: close: Langsung tutup
            close(sock_client);
        }

        // 3. Selesai proses, tandai thread kembali IDLE
        mark_worker_idle(&global_queue);
    }
    return NULL;
}

/********************************************************************
 * handle_client()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti kepala pelayan yang menentukan:
 *
 * - Tamu ini harus diarahkan ke ruang HTTP1?
 * - Atau ruang HTTP2?
 *
 * Dia tidak memasak sendiri,
 * hanya menentukan jalur layanan yang tepat.
 ********************************************************************/
int handle_client(int sock_client) {
    protocol_type_t proto = detect_protocol(sock_client);

    if (proto == PROTO_HTTP2) {
        send_mem_response(sock_client, 505, "Not Supported", "<h1>H2 Soon</h1>", false);
        return 0; 
    } 
    else {
        return handle_http1_session(sock_client);
    }
}