#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

// Header internal Anda
#include "../include/http.h"
#include "../include/config.h"
#include "../include/log.h"

#define CONFIG_FILE "/etc/halmos/halmos.conf"
#define THREAD_COUNT 4
#define QUEUE_SIZE 1024

// Variabel Global
Config config;
int sock_server;
int epoll_fd;
struct epoll_event *events;
int MAX_EVENTS;

// --- STRUKTUR THREAD POOL ---
typedef struct {
    int client_fds[QUEUE_SIZE];
    int head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
} ThreadPool;

ThreadPool pool;

// --- FUNGSI UTILITAS ---

// Perbaikan fungsi non-blocking agar benar secara bitwise
void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// --- LOGIKA HANDLING CLIENT ---
void handle_client(int sock_client) {
    int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) return;

    // 1. Baca data pertama
    ssize_t received = recv(sock_client, buffer, buf_size - 1, 0);
    if (received <= 0) { free(buffer); close(sock_client); return; }
    buffer[received] = '\0';

    // 2. Pre-Parsing
    RequestHeader req_header = parse_request_line(buffer, (size_t)received);
    
    // KEKURANGAN 1: Cek validitas header
    if (!req_header.is_valid) {
        send_mem_response(sock_client, 400, "Bad Request", "<h1>400 Bad Request</h1>");
        free(buffer);
        free_request_header(&req_header);
        close(sock_client);
        return;
    }

    // 3. Baca sisa body jika belum lengkap
    if (req_header.content_length > 0 && req_header.body_length < (size_t)req_header.content_length) {
        
        size_t max_allowed = config.max_body_size > 0 ? config.max_body_size : (10 * 1024 * 1024);
        if ((size_t)req_header.content_length > max_allowed) {
            send_mem_response(sock_client, 413, "Payload Too Large", "<h1>413 Payload Too Large</h1>");
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return;
        }

        // KEKURANGAN 2: Realloc yang aman
        void *new_body = realloc(req_header.body_data, req_header.content_length + 1);
        if (!new_body) { 
            write_log("Out of memory during body realloc");
            free(buffer);
            free_request_header(&req_header);
            close(sock_client);
            return; 
        }
        req_header.body_data = new_body;

        char *ptr = (char *)req_header.body_data + req_header.body_length;
        size_t total_needed = req_header.content_length - req_header.body_length;

        int retry_count = 0;
        const int MAX_RETRY = 5000; // Total tunggu maksimal ~5 detik

        while (total_needed > 0 && retry_count < MAX_RETRY) {
            ssize_t n = recv(sock_client, ptr, total_needed, 0);
            if (n > 0) {
                ptr += n;
                total_needed -= n;
                req_header.body_length += n;
                retry_count = 0; // Reset retry jika ada data masuk
            } else if (n == 0) {
                break; // Client menutup koneksi
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Data belum sampai di buffer OS, tunggu sebentar (micro-sleep)
                    // Atau idealnya kembalikan ke epoll, tapi untuk simplicity:
                    usleep(1000);
                    retry_count++; 
                    continue;
                }
                break; // Error beneran
            }
        }

        if (retry_count >= MAX_RETRY) {
            write_log("Timeout: Client failed to send full body");
            send_mem_response(sock_client, 408, "Request Timeout", "<h1>408 Request Timeout</h1>");
            free(buffer);
            free_request_header(&req_header);
            close(sock_client); // Tutup koneksi karena data tidak lengkap
            return;
        }

        ((char*)req_header.body_data)[req_header.body_length] = '\0';

        // KEKURANGAN 3: Parsing ulang multipart SETELAH body lengkap
        if (req_header.content_type && strstr(req_header.content_type, "multipart/form-data")) {
            // Panggil parser multipart di sini agar memproses data yang sudah utuh
            parse_multipart_body(&req_header);
        }
    }

    free(buffer); 

    // 4. Proses Method
    handle_method(sock_client, req_header);

    free_request_header(&req_header);
    
    // JANGAN close(sock_client) di sini jika ingin re-arm epoll untuk Keep-Alive
    // Kecuali memang ingin satu request satu koneksi (Connection: close)

    //close(sock_client);
}

// --- FUNGSI WORKER THREAD ---
void* worker_routine(void* arg) {
    while (1) {
        pthread_mutex_lock(&pool.lock);
        while (pool.count == 0) {
            pthread_cond_wait(&pool.not_empty, &pool.lock);
        }

        int sock_client = pool.client_fds[pool.head];
        pool.head = (pool.head + 1) % QUEUE_SIZE;
        pool.count--;
        pthread_mutex_unlock(&pool.lock);

        handle_client(sock_client);

        // REARM EPOLL: Aktifkan kembali ONESHOT agar bisa menerima request selanjutnya
        // Ini untuk menangani koneksi Keep-Alive
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
        ev.data.fd = sock_client;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock_client, &ev) == -1) {
            // Jika gagal re-arm (misal FD sudah tertutup), pastikan benar-benar close
            close(sock_client);
        }
    }
    return NULL;
}

// --- INISIALISASI ---
void init_thread_pool() {
    pool.head = pool.tail = pool.count = 0;
    pthread_mutex_init(&pool.lock, NULL);
    pthread_cond_init(&pool.not_empty, NULL);

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, worker_routine, NULL) != 0) {
            write_log("Gagal membuat thread pekerja %d", i);
        }
        pthread_detach(tid); 
    }
}

void start_server() {
    MAX_EVENTS = config.max_event > 0 ? config.max_event : 64;
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

void run_server_loop() {
    while (1) {
        int num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < num_fds; i++) {
            if (events[i].data.fd == sock_server) {
                // Koneksi Baru masuk
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int sock_client = accept(sock_server, (struct sockaddr *)&client_addr, &addr_len);
                
                if (sock_client < 0) continue;

                set_nonblocking(sock_client);
                struct epoll_event ev_client;
                ev_client.data.fd = sock_client;
                // Edge Triggered + One Shot untuk sinkronisasi thread
                ev_client.events = EPOLLIN | EPOLLET | EPOLLONESHOT; 
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_client, &ev_client);
            } else {
                // Event pada socket client existing
                int client_fd = events[i].data.fd;

                pthread_mutex_lock(&pool.lock);
                if (pool.count < QUEUE_SIZE) {
                    pool.client_fds[pool.tail] = client_fd;
                    pool.tail = (pool.tail + 1) % QUEUE_SIZE;
                    pool.count++;
                    pthread_cond_signal(&pool.not_empty);
                } else {
                    write_log("Antrean penuh, menolak koneksi %d", client_fd);
                    close(client_fd);
                }
                pthread_mutex_unlock(&pool.lock);
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

void set_daemon() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    if (devnull > 2) close(devnull);
}

int main() {
    // Abaikan SIGPIPE agar tidak crash jika client putus saat sendfile
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);

    load_config(CONFIG_FILE);

    // Aktifkan mode daemon jika diperlukan
    // set_daemon();

    init_thread_pool();
    start_server();
    run_server_loop();

    return 0;
}