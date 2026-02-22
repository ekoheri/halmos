#include "halmos_event_loop.h"
#include "halmos_global.h"
#include "halmos_tcp_server.h"
#include "halmos_config.h"
#include "halmos_log.h"
#include "halmos_queue.h"
#include "halmos_security.h"
#include "halmos_route.h"
#include "halmos_tls.h"
#include "halmos_ipc_bridge.h"

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
#include <signal.h>

// Pemilik variable global
int epoll_fd;
int bridge_fd;
struct epoll_event *events;

//Variable Local
int sock_server;

volatile sig_atomic_t server_running = 1;

void start_event_loop() {
    // 1. aktifkan epoll
    // menghitung berapa jumlah core untuk 
    // patokan berapa jumlah event pool yang cocok
    events = malloc(sizeof(struct epoll_event) * g_event_batch_size);

    sock_server = create_server_socket(config.server_name, config.server_port);
    if (sock_server < 0) {
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    struct epoll_event ev;
    ev.data.fd = sock_server;
    ev.events = EPOLLIN; // Level Triggered untuk listen socket
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_server, &ev);

    //---------- Panggil IPC-Bridge

    bridge_fd = setup_uds_bridge("/tmp/halmos_bridge.sock");

    // 2. Tambahkan ke epoll
    struct epoll_event ev_bridge;
    ev_bridge.data.fd = bridge_fd;
    ev_bridge.events = EPOLLIN; // Cukup EPOLLIN, tidak perlu ONESHOT
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bridge_fd, &ev_bridge);

    write_log("[CORE] Server listening on %s:%d", config.server_name, config.server_port);
}

void run_event_loop() {
    while (server_running) {
        halmos_router_auto_reload();

        int num_fds = epoll_wait(epoll_fd, events, g_event_batch_size, 500); // awalnya -1
        if (num_fds < 0) {
            if (errno != EINTR) {
                write_log_error("[CORE] epoll_wait critical error: %s", strerror(errno));
            }
            continue; // Jangan for-loop kalau error
        }

        for (int i = 0; i < num_fds; i++) {
            int current_fd = events[i].data.fd;
            if (current_fd == sock_server) {
                // LOOP ACCEPT: Ambil semua tamu yang antre sampai ludes
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    int sock_client = accept(sock_server, (struct sockaddr *)&client_addr, &addr_len);
                    
                    if (sock_client < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break; 
                        }
                        if (errno == EINTR) continue;

                        // Tambahkan keterangan errno biar tidak menebak-nebak
                        write_log_error("[ERR] Accept failed:: %s (Errno: %d)", strerror(errno), errno);
                        
                        // Jika karena limit file descriptor (EMFILE), kita harus berhenti sebentar
                        if (errno == EMFILE || errno == ENFILE) {
                            // Kasih jeda 1ms biar kernel bisa bersih-bersih FD lama
                            usleep(1000); 
                        }
                        break;
                    }
                    global_telemetry.active_connections++; // Tambah saat ada tamu masuk

                    // --- PANGGIL ANTI SLOW LORIS ---
                    // Jika di konfigurasi diset true
                    if(config.anti_slow_loris_enabled == true){
                        anti_slow_loris(sock_client);
                    }
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
                       // Jika gagal karena FD sudah tidak ada (EBADF), jangan panik
                        if (errno == EBADF) {
                            // Cukup tutup saja, tidak perlu lapor perror yang bikin panik
                            close(sock_client); 
                        } else {
                            // Jika error lain (misal ENOMEM), baru kita catat
                            write_log_error("[CRIT] Epoll add failed for client FD %d: %s", sock_client, strerror(errno));
                            close(sock_client);
                        }
                    }
                }
            } else if(current_fd == bridge_fd) {
                handle_bridge_request(bridge_fd);
            } else {
                // --- BAGIAN YANG DIUBAH (RAMPING & AMAN) ---
                int client_fd = events[i].data.fd;

                // CEK ERROR: Jika socket bermasalah, jangan masukkan ke antrean
                if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    write_log_error("[NET] Closing FD %d (EPOLLERR/HUP)", client_fd);

                    global_telemetry.active_connections--; // <--- TAMBAHKAN INI! Tamu batal masuk.
                    // PENTING: Bersihkan sisa-sisa SSL di mapping table sebelum FD ditutup!

                    cleanup_connection_properly(client_fd);
                    
                    close(client_fd);
                    continue;
                }

                // 1. Masukkan ke antrean TANPA memanipulasi epoll di sini.
                // Karena kita pakai EPOLLONESHOT, kernel otomatis menonaktifkan
                // FD ini dari epoll_wait sampai ada yang panggil MOD lagi.
                int status = enqueue(&global_queue, client_fd); 

                if (status < 0) {
                    if (status == -1) {
                        write_log_error("[CORE] Worker queue full! Rejecting FD %d with 503", client_fd);
                        char *res = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(client_fd, res, strlen(res), 0);
                    } else {
                        write_log_error("[CORE] Enqueue failed for FD %d (Internal Error)", client_fd);
                    }

                    global_telemetry.active_connections--; // Kurangi karena gagal/tutup

                    // Hapus dulu dari epoll sebelum close
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
                    shutdown(client_fd, SHUT_RDWR); // Pastikan browser tidak nunggu
                    close(client_fd);
                }
            }
        }
    }

    close(sock_server);
    close(epoll_fd);
    free(events);

    write_log("[CORE] Server stopped. Resource cleanup complete."); 
}

void stop_event_loop(int sig) {
    (void)sig;
    server_running = 0;
}

/**
 * REARM EPOLL ONESHOT
 * Analogi: Pelayan (Worker) melapor ke Resepsionis (Epoll) 
 * bahwa meja ini sudah selesai dibersihkan dan siap menerima pesanan lagi.
 */
void rearm_epoll_oneshot(int fd) {
    struct epoll_event ev;
    // Kembalikan status ke mode pantau: Read + Edge-Triggered + One-Shot
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        // Kita log error-nya, kecuali kalau socket-nya memang sudah keburu tutup (EBADF)
        if (errno != EBADF) {
            write_log_error("[NET] Failed to re-arm epoll for FD %d: %s", fd, strerror(errno));
        }
    }
}

