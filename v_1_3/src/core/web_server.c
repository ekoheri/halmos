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

// Header internal Anda
#include "../include/core/web_server.h"
#include "../include/core/log.h"
#include "../include/protocols/common/http_common.h"
#include "../include/protocols/http1/http1_parser.h"
#include "../include/protocols/http1/http1_response.h"
#include "../include/handlers/multipart.h"

#define CONFIG_FILE "/etc/halmos/halmos.conf"

int sock_server;
int epoll_fd;
struct epoll_event *events;
int MAX_EVENTS;


void set_daemon() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); 

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); 

    umask(0);
    
    int devnull = open("/dev/null", O_RDWR);
    if (devnull != -1) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
}

// --- FUNGSI UTILITAS ---
void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        write_log("Error : fcntl F_GETFL");
        return;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        write_log("Error : fcntl F_SETFL");
    }
}

// DETECT PROTOCOL HTTP1/HTTP2
/**
 * Mendeteksi jenis protokol tanpa menghapus data dari buffer socket.
 */
protocol_type_t detect_protocol(int client_fd) {
    char buffer[24];
    // MSG_PEEK membiarkan data tetap ada di kernel untuk dibaca recv() nanti
    ssize_t n = recv(client_fd, buffer, sizeof(buffer), MSG_PEEK);
    
    if (n <= 0) return PROTO_UNKNOWN;

    // Cek Magic String HTTP/2: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if (n >= 24 && memcmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        return PROTO_HTTP2;
    }

    // Jika diawali string metode HTTP umum, maka itu HTTP/1
    if (n >= 3 && (memcmp(buffer, "GET", 3) == 0 || 
                   memcmp(buffer, "POS", 3) == 0 || 
                   memcmp(buffer, "HEA", 3) == 0 ||
                   memcmp(buffer, "PUT", 3) == 0 ||
                   memcmp(buffer, "DEL", 3) == 0)) {
        return PROTO_HTTP1;
    }

    // Default jika tidak yakin, biarkan HTTP/1 manager yang mencoba memprosesnya
    return PROTO_HTTP1;
}

// --- LOGIKA HANDLING CLIENT ---
/**
 * DISPATCHER UTAMA
 * Fungsi ini dijalankan oleh Worker Thread saat ada koneksi masuk.
 */
int handle_client(int sock_client) {
    // 1. Deteksi Protokol
    protocol_type_t proto = detect_protocol(sock_client);

    if (proto == PROTO_HTTP2) {
        send_mem_response(sock_client, 505, "Not Supported", "<h1>H2 Soon</h1>", false);
        return 0; // Beritahu worker untuk tutup koneksi
    } 
    else {
        // JALANKAN SATU KALI SAJA (Tanpa While)
        // handle_http1_session akan memproses 1 request, lalu return 1 jika keep-alive
        return handle_http1_session(sock_client);
    }
}

// --- FUNGSI WORKER THREAD ---
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

void start_server() {
    // --- LOGIKA ADAPTIVE MAX_EVENTS ---
    struct rlimit rl;
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
    
    struct sockaddr_in serv_addr;
    int opt = 1;

    sock_server = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_server < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bypass "Address already in use"
    setsockopt(sock_server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(sock_server);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(config.server_name);
    serv_addr.sin_port = htons(config.server_port);

    if (bind(sock_server, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        write_log("Proses bind gagal pada %s:%d", config.server_name, config.server_port);
        exit(EXIT_FAILURE);
    }

    if (listen(sock_server, 128) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    struct epoll_event ev;
    ev.data.fd = sock_server;
    ev.events = EPOLLIN; // Level Triggered untuk listen socket
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_server, &ev);

    write_log("Halmos Server berjalan di %s:%d", config.server_name, config.server_port);
}

// --- MAIN LOOP (PRODUCER) ---
void run_server() {
    while (1) {
        int num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        
        for (int i = 0; i < num_fds; i++) {
            if (events[i].data.fd == sock_server) {
                // KONEKSI BARU
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int sock_client = accept(sock_server, (struct sockaddr *)&client_addr, &addr_len);
                
                if (sock_client < 0) continue;

                set_nonblocking(sock_client);
                struct epoll_event ev_client;
                ev_client.data.fd = sock_client;
                ev_client.events = EPOLLIN | EPOLLET | EPOLLONESHOT; 
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_client, &ev_client);
                
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

void stop_server(int sig) {
    write_log("Menerima sinyal %d, menghentikan server...", sig);
    close(sock_server);
    if (events) free(events);
    exit(0);
}
