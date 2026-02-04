#include "halmos_event_loop.h"
#include "halmos_global.h"
#include "halmos_tcp_server.h"
#include "halmos_config.h"
#include "halmos_log.h"
#include "halmos_queue.h"
#include "halmos_security.h"

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
struct epoll_event *events;

//Variable Local
int sock_server;

volatile sig_atomic_t server_running = 1;

void start_event_loop() {
    // menghitung berapa jumah core untuk 
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

    write_log("Halmos Server listening on %s:%d", config.server_name, config.server_port);
}

void run_event_loop() {
    while (server_running) {
        int num_fds = epoll_wait(epoll_fd, events, g_event_batch_size, 500); // awalnya -1
        
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
                        
                        write_log_error("Accept failed");
                        break;
                    }

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
                    //write_log("REJECTED: Queue is full (%d)", global_queue.max_queue_limit);
                } else if (status == -2) {
                    // Gagal Malloc (RAM Habis)
                    close(client_fd);
                    //write_log("CRITICAL: Malloc failed for new task");
                }
            }
        }
    }

    close(sock_server);
    close(epoll_fd);
    free(events);

    write_log("Server Halmos is stopped. Cleanup complete."); 
}

void stop_event_loop(int sig) {
    (void)sig;
    server_running = 0;
}
