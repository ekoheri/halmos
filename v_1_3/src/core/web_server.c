#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <poll.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// Header internal Anda
#include "web_server.h"
#include "log.h"
#include "http_common.h"
#include "http1_parser.h"
#include "http1_response.h"
#include "multipart.h"
#include "queue.h"
#include "event_handler.h"
#include "network_handler.h"

#define CONFIG_FILE "/etc/halmos/halmos.conf"

int sock_server;
int epoll_fd;
struct epoll_event *events;
int MAX_EVENTS;

TaskQueue global_queue;

/********************************************************************
 * start_server()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti membuka cabang restoran baru:
 *
 * - Menentukan kapasitas kursi (MAX_EVENTS)
 *   berdasarkan ukuran gedung (ulimit).
 *
 * - Membuat pintu masuk utama (socket listen).
 * - Memasang resepsionis epoll sebagai
 *   sistem antrian elektronik.
 *
 * Level Triggered pada listen socket =
 * resepsionis selalu sadar kalau ada tamu baru.
 ********************************************************************/
void start_server() {
    setup_event_system();
    
    sock_server = create_server_socket(config.server_name, config.server_port);
    if (sock_server < 0) {
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    struct epoll_event ev;
    ev.data.fd = sock_server;
    ev.events = EPOLLIN; // Level Triggered untuk listen socket
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_server, &ev);

    write_log("[INFO] Halmos Server listening on %s:%d", config.server_name, config.server_port);
}

/**
 * Persiapkan socket client sebelum masuk ke epoll.
 * - Set Timeout (Anti-Slowloris & Keep-Alive)
 * - Set Non-blocking (Wajib buat epoll ET)
 * - TCP_NODELAY (Opsional: biar respon lebih gesit)
 */
void setup_socket_security(int sock_client) {
    // 1. Ambil napas dari config
    struct timeval tv;
    tv.tv_sec = config.keep_alive_timeout > 0 ? config.keep_alive_timeout : 5;
    tv.tv_usec = 0;

    // 2. Pasang sumbu (Anti-Slowloris)
    setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // 3. Optimasi: Kirim data tanpa nunggu (Nagle's Algorithm Off)
    int opt = 1;
    setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

/********************************************************************
 * run_server()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini adalah RESEPSIONIS utama restoran (event-driven core).
 *
 * - epoll_wait() = resepsionis melihat bel notifikasi:
 *   “Meja mana yang manggil?”
 *
 * Jika event dari pintu utama:
 *   → tamu baru datang → buat meja baru.
 *
 * Jika event dari klien lama:
 *   → nota pesanan dimasukkan ke antrean dapur
 *     (enqueue ke worker).
 *
 * Kalau antrean penuh:
 *   → resepsionis menolak dengan sopan 503.
 ********************************************************************/
void run_server() {
    while (1) {
        int num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        
        for (int i = 0; i < num_fds; i++) {
            if (events[i].data.fd == sock_server) {
                // LOOP ACCEPT: Ambil semua tamu yang antre sampai ludes
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    int sock_client = accept(sock_server, (struct sockaddr *)&client_addr, &addr_len);
                    
                    if (sock_client < 0) {
                        // Jika errno EAGAIN atau EWOULDBLOCK, artinya antrean tamu sudah habis
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break; 
                        }
                        // Jika interupsi signal, coba lagi
                        if (errno == EINTR) continue;
                        
                        perror("Accept failed");
                        break;
                    }

                    // --- PANGGIL WNTO SLOW LORIS ---
                    setup_socket_security(sock_client);
                    // -------------------------

                    // Set tamu jadi non-blocking agar tidak bikin thread pool macet
                    set_nonblocking(sock_client);

                    struct epoll_event ev_client;
                    ev_client.data.fd = sock_client;
                    // EPOLLONESHOT = Begitu resepsionis minta satu pelayan (worker thread) 
                    // buat ngurus meja nomor 5, resepsionis bakal "tutup mata" 
                    // terhadap meja nomor 5 itu. 
                    // Dia nggak bakal manggil pelayan lain buat meja yang sama 
                    // sampai pelayan pertama bilang "Selesai!".
                    ev_client.events = EPOLLIN | EPOLLET | EPOLLONESHOT; 
                    
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_client, &ev_client) == -1) {
                        perror("epoll_ctl: client_socket");
                        close(sock_client);
                    }
                }
            } else {
                // REQUEST MASUK DARI CLIENT EXISTING
                int client_fd = events[i].data.fd;

                // Masukkan socket ke antrean TaskQueue
                int status = enqueue(&global_queue, client_fd); 

                if (status == -1) {
                    // Antrean Penuh
                    char *res = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send(client_fd, res, strlen(res), 0);
                    close(client_fd);
                    write_log("REJECTED: Queue is full (%d)", global_queue.max_queue_limit);
                } else if (status == -2) {
                    // Gagal Malloc (RAM Habis)
                    close(client_fd);
                    write_log("CRITICAL: Malloc failed for new task");
                }
            }
        }
    }
}

/********************************************************************
 * stop_server()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti manajer restoran menerima perintah tutup:
 *
 * - Mengumumkan ke log,
 * - Mengunci pintu masuk,
 * - Membersihkan ruang resepsionis (free events),
 * - Mematikan operasional dengan rapi.
 ********************************************************************/
void stop_server(int sig) {
    write_log("Menerima sinyal %d, menghentikan server...", sig);
    close(sock_server);
    if (events) free(events);
    exit(0);
}
