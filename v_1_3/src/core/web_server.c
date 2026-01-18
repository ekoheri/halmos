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


/********************************************************************
 * set_nonblocking()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti mengubah cara pelayan bekerja.
 *
 * Normal blocking:
 *   Pelayan menunggu satu pelanggan selesai bicara dulu
 *   baru bisa melayani yang lain.
 *
 * Non-blocking:
 *   Pelayan bisa bilang:
 *   “Silakan pikir dulu pesanannya, saya layani meja lain.”
 *
 * Sehingga satu thread tidak tersandera oleh satu klien.
 ********************************************************************/
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

/********************************************************************
 * detect_protocol()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti resepsionis yang hanya “mengintip” gaya bicara tamu
 * tanpa langsung mengajaknya ngobrol.
 *
 * - Kalau tamu membuka dengan kalimat resmi ala HTTP/2,
 *   berarti tamu VIP (HTTP2).
 * - Kalau mulai dengan “GET /”, “POST /” → tamu biasa HTTP/1.
 *
 * MSG_PEEK = mengintip tanpa menghapus data asli,
 * seperti melihat dari balik kaca tanpa memanggil tamu masuk.
 ********************************************************************/

protocol_type_t detect_protocol(int client_fd) {
    char buffer[24];
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
