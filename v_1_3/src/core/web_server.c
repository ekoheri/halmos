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

// Objek Antrean Global (Pusat Kendali)
TaskQueue global_queue;

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

// --- LOGIKA HANDLING CLIENT ---
int handle_client(int sock_client) {
    int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) return 0; // Kembalikan 0 jika gagal alokasi

    // 1. Baca data pertama
    ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
    if (received <= 0) { 
        free(buffer); 
        close(sock_client); 
        return 0; // Gagal baca, tutup koneksi
    }
    buffer[received] = '\0';

    // 2. Eksekusi Parsing (Memanggil modul http_parser.c)
    // Kita gunakan parse_http_request yang di dalamnya sudah mencakup 
    // logika parse_request_line kompleks.

    RequestHeader req_header; 
    memset(&req_header, 0, sizeof(RequestHeader));
    
    bool success = parse_http_request(buffer, (size_t)received, &req_header);

    // 3. Cek validitas (Sesuai dengan logika asli Anda)
    if (!success || !req_header.is_valid) {
        // Memanggil fungsi response (nanti ada di http_response.c)
        send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>", false);
        
        // Pembersihan sesuai kebutuhan
        free_request_header(&req_header); 
        close(sock_client);
        return 0; 
    }

    // 3. Baca sisa body jika belum lengkap
    if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
        
        size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
        if ((size_t)req_header.content_length > max_allowed) {
            send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413 Payload Too Large</h1>", false);
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0;
        }

        void *new_body = realloc(req_header.body_data, req_header.content_length + 1);
        if (!new_body) { 
            write_log("Out of memory during body realloc");
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0; 
        }
        req_header.body_data = new_body;

        char *ptr = (char *)req_header.body_data + req_header.body_length;
        size_t total_needed = req_header.content_length - req_header.body_length;

        int retry_count = 0;
        const int MAX_RETRY = 5000;

        while (total_needed > 0 && retry_count < MAX_RETRY) {
            ssize_t n = recv(sock_client, ptr, total_needed, 0);
            if (n > 0) {
                ptr += n;
                total_needed -= n;
                req_header.body_length += n;
                retry_count = 0;
            } else if (n == 0) {
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd;
                    pfd.fd = sock_client;
                    pfd.events = POLLIN;
                    // Tunggu maksimal 100ms, tapi bangun seketika data datang
                    int poll_res = poll(&pfd, 1, 100); 
                    if (poll_res <= 0) retry_count++; 
                    continue;
                }
                break;
            }
        }

        if (retry_count >= MAX_RETRY) {
            write_log("Timeout: Client failed to send full body");
            send_mem_response(sock_client, 408, "Request Timeout", "<h1>408 Request Timeout</h1>", false);
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return 0;
        }

        ((char*)req_header.body_data)[req_header.body_length] = '\0';

        // khusus menangani post data multipart
        if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
            parse_multipart_body(&req_header);
        }
    }

    free(buffer); 

    // Ambil status sebelum struct dibebaskan
    int keep_alive_status = req_header.is_keep_alive;

    // 1. TAMBAHKAN DISINI (Logika ambil IP)
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "0.0.0.0";

    // Fungsi getpeername mengambil info dari socket yang sedang aktif
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    // 2. MODIFIKASI write_log Anda
    write_log("Thread Monitoring | IP: %s | Active: %d/%d | Request: %s | Method: %s | Connection: %s",
          client_ip, // <-- Tambahkan variabel IP di sini
          global_queue.active_workers, 
          global_queue.total_workers,
          req_header.uri,
          req_header.method,
          keep_alive_status ? "Keep-Alive" : "Close");
          
    // 5. Proses Method
    handle_method(sock_client, req_header);

    // Tambahkan Log Monitoring
    write_log("Thread Monitoring | Active: %d/%d | Request: %s | Method: %s | Connection: %s",
          global_queue.active_workers, 
          global_queue.total_workers,
          req_header.uri,
          req_header.method,
          keep_alive_status ? "Keep-Alive" : "Close");

    free_request_header(&req_header);
    
    // Logika Hybrid: Jika bukan keep-alive, tutup socket di sini
    if (!keep_alive_status) {
        close(sock_client);
    }

    return keep_alive_status;
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
