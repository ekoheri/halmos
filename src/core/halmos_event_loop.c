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

//Variable Global
Config config;
int epoll_fd;
struct epoll_event *events;
int max_event_loop;

//Variable Local
int sock_server;

void allocate_loop_resource();

void start_event_loop() {
    // menghitung berapa jumah core untuk 
    // patokan berap jumlah event pool yang cocok
    allocate_loop_resource();
    
    sock_server = create_server_socket(config.server_name, config.server_port);
    if (sock_server < 0) {
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    struct epoll_event ev;
    ev.data.fd = sock_server;
    ev.events = EPOLLIN; // Level Triggered untuk listen socket
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_server, &ev);

    write_log("[INFO: halmos_event_loop.c] Halmos Server listening on %s:%d", config.server_name, config.server_port);
}

void run_event_loop() {
    while (1) {
        int num_fds = epoll_wait(epoll_fd, events, max_event_loop, -1);
        
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
                    //if(config.anti_slow_loris_enabled){
                    //    anti_slow_loris(sock_client);
                    //}
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
}

void stop_event_loop() {
    exit(0);
}

/********************************************************************
 * adaptive_resource_setup()
 * ISI : Sama persis logika ulimit & 10% MAX_EVENTS Boss.
 ********************************************************************/
void allocate_loop_resource() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        // Naikkkan ke Hard Limit
        rl.rlim_cur = rl.rlim_max; 
        setrlimit(RLIMIT_NOFILE, &rl);
        
        // Adaptive: Ambil 10% untuk batching
        max_event_loop = (int)(rl.rlim_cur / 10);
        if (max_event_loop < 64)   max_event_loop = 64;
        if (max_event_loop > 1024) max_event_loop = 1024;
        
        write_log("[ADAPTIVE] Max Events set to: %d", max_event_loop);
    }
    events = malloc(sizeof(struct epoll_event) * max_event_loop);
}
