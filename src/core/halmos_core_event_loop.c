#include "halmos_global.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_config.h"
#include "halmos_core_tcp_server.h"
#include "halmos_core_connection.h"
#include "halmos_core_queue.h"
#include "halmos_log.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_ws_system.h"
#include "halmos_ws_ipc.h"

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

// PERBAIKAN: Mengubah void menjadi int
int event_loop_start(void) {
    server_running = 1;

    events = malloc(sizeof(struct epoll_event) * g_event_batch_size);
    if (!events) {
        write_log_error("[FATAL] Failed to allocate memory for epoll events");
        return -1;
    }

    sock_server = tcp_create_server(config.server_name, config.server_port);
    if (sock_server < 0) {
        write_log_error("[FATAL] Failed to bind TCP listener on %s:%d", 
                config.server_name, config.server_port);
        free(events);
        events = NULL;
        return -1; // PERBAIKAN: Return -1, bukan exit(EXIT_FAILURE)
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { // PERBAIKAN: Cek kegagalan epoll_create1
        write_log_error("[FATAL] epoll_create1 failed: %s", strerror(errno));
        close(sock_server);
        free(events);
        events = NULL;
        return -1;
    }

    struct epoll_event ev;
    ev.data.fd = sock_server;
    ev.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_server, &ev) < 0) {
        write_log_error("[FATAL] Failed to add sock_server to epoll: %s", strerror(errno));
        close(sock_server);
        close(epoll_fd);
        free(events);
        events = NULL;
        return -1;
    }

    bridge_fd = setup_uds_bridge("/tmp/halmos_bridge.sock");
    if (bridge_fd >= 0) {
        struct epoll_event ev_bridge;
        ev_bridge.data.fd = bridge_fd;
        ev_bridge.events = EPOLLIN;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bridge_fd, &ev_bridge);
    } else {
        write_log_error("[WARN] IPC UDS Bridge initialization failed.");
    }

    write_log("[CORE] Server listening on %s:%d", config.server_name, config.server_port);
    return 0; // PERBAIKAN: Return 0 jika sukses
}

void event_loop_run() {
    while (server_running) {
        // http_route_auto_reload();
        http_vhost_reload_routes();

        int num_fds = epoll_wait(epoll_fd, events, g_event_batch_size, 100); // awalnya -1
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
                while (server_running) {
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

                    // Set SO_RCVTIMEO agar worker tidak menggantung di read socket I/O (Keep-Alive Safety)
                    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
                    setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(sock_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                    global_telemetry.active_connections++; // Tambah saat ada tamu masuk

                    // === MODIFIKASI 2: Aktifkan slot tracking koneksi & ambil generation baru ===
                    uint32_t conn_gen = core_conn_activate(sock_client);
                    if (conn_gen == 0) {
                        // FD berada di luar jangkauan g_max_fd
                        write_log_error("[CRIT] FD %d exceeds g_max_fd capacity", sock_client);
                        close(sock_client);
                        global_telemetry.active_connections--;
                        break;
                    }

                    // --- PANGGIL ANTI SLOW LORIS ---
                    // Jika di konfigurasi diset true
                    if(config.anti_slow_loris_enabled == true){
                        sec_traffic_anti_slow_loris(sock_client);
                    }
                    // -------------------------

                    // Set tamu jadi non-blocking agar tidak bikin thread pool macet
                    tcp_set_nonblocking(sock_client);

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
                int client_fd = events[i].data.fd;
                uint32_t ev = events[i].events;

                // 1. CEK ERROR / DISCONNECT DULU
                if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    write_log_error("[NET] Closing FD %d (EPOLLERR/HUP/RDHUP)", client_fd);
                    global_telemetry.active_connections--;
                    event_loop_cleanup_connection(client_fd);
                    continue;
                }

                // 2. CEK I/O EVENT (BACA ATAU TULIS)
                if (ev & (EPOLLIN | EPOLLOUT)) {
                    if (!server_running) {
                        // === MODIFIKASI 3A: Deaktivasi connection state sebelum close ===
                        core_conn_deactivate(client_fd);
                        close(client_fd);
                        continue;
                    }

                    // === MODIFIKASI 3B: Bungkus FD & Generation ke halmos_event_t ===
                    halmos_conn_t *conn = core_conn_get(client_fd);
                    if (!conn || !atomic_load(&conn->active)) {
                        // Skip jika koneksi sudah tidak aktif/invalid
                        continue;
                    }
                    
                    halmos_event_t event_item = {
                        .fd = client_fd,
                        .generation = atomic_load(&conn->generation)
                    };

                    int status = queue_push(&global_queue, event_item);
                    //int status = queue_push(&global_queue, client_fd); 

                    if (status < 0) {
                        if (status == -1) {
                            write_log_error("[CORE] Worker queue full! Rejecting FD %d with 503", client_fd);
                            char *res = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            send(client_fd, res, strlen(res), 0);
                        } else {
                            write_log_error("[CORE] Enqueue failed for FD %d (Internal Error)", client_fd);
                        }

                        global_telemetry.active_connections--;
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);

                        // === MODIFIKASI 3C: Reset atomic state koneksi ===
                        core_conn_deactivate(client_fd);

                        shutdown(client_fd, SHUT_RDWR);
                        close(client_fd);
                    }
                }
            }
        }
    }

    // Cleanup resources setelah loop berhenti
    if (bridge_fd >= 0) {
        close(bridge_fd);
        unlink("/tmp/halmos_bridge.sock");
        bridge_fd = -1;
    }
    
    if (sock_server >= 0) {
        close(sock_server);
        sock_server = -1;
    }
    
    if (epoll_fd >= 0) {
        close(epoll_fd);
        epoll_fd = -1;
    }
    
    if (events) {
        free(events);
        events = NULL;
    }

    write_log("[CORE] Server stopped. Resource cleanup complete."); 
}

void event_loop_stop(void) {
    //(void)sig;
    server_running = 0;

    // 1. Tutup listener socket agar accept() tidak lagi menerima koneksi baru
    if (sock_server >= 0) {
        close(sock_server);
        sock_server = -1;
    }

    // 2. Bangunkan thread pool worker secara paksa 
    // agar mereka tidak menunggu timeout timedwait di queue_pop
    pthread_mutex_lock(&global_queue.lock);
    global_queue.is_running = 0;
    pthread_cond_broadcast(&global_queue.cond);
    pthread_mutex_unlock(&global_queue.lock);
}

/**
 * REARM EPOLL ONESHOT
 * Analogi: Pelayan (Worker) melapor ke Resepsionis (Epoll) 
 * bahwa meja ini sudah selesai dibersihkan dan siap menerima pesanan lagi.
 */

void event_loop_rearm_epoll_ex(int fd, uint32_t events_mask) {
    struct epoll_event ev;
    // Selalu sertakan EPOLLET (Edge Triggered) dan EPOLLONESHOT
    ev.events = events_mask | EPOLLET | EPOLLONESHOT;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        if (errno != EBADF) {
            write_log_error("[NET] Failed to re-arm epoll for FD %d: %s", fd, strerror(errno));
        }
    }
} 
void event_loop_rearm_epoll(int fd) {
    event_loop_rearm_epoll_ex(fd, EPOLLIN | EPOLLOUT);
}

void event_loop_cleanup_connection(int sock_client) {
    // === MODIFIKASI 4: Matikan status aktif atomic connection ===
    core_conn_deactivate(sock_client);
    
    // --- [ TAMBAHAN UNTUK WEBSOCKET ] ---
    // Pastikan flag WS dihapus sebelum FD ini dipakai ulang oleh kernel
    ws_system_cleanup_fd(sock_client);

    // 1. Ambil SSL-nya (kalau ada)
    SSL *ssl = ssl_get_for_fd(sock_client);

    // 2. Cabut dari map biar thread lain nggak ganggu
    ssl_nullify_ptr(sock_client); 
    
    if (ssl) {
        // Cek dulu apa ada error nyangkut di OpenSSL sebelum dibuang
        unsigned long err_code = ERR_peek_last_error(); 
        if (err_code != 0) {
            write_log_error("[SEC] Ending FD %d with SSL error: %s", 
                            sock_client, ERR_error_string(err_code, NULL));
        }

        // SSL_shutdown kirim "Close Notify" (sopan)
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ERR_clear_error(); // Bersihkan error queue per-thread
    }

    // 3. SHUTDOWN TCP (Graceful)
    // Kirim paket FIN, bukan RST
    shutdown(sock_client, SHUT_WR);

    // 4. DRAIN (Kuras data sisa agar kernel nggak kirim RST)
    char junk[1024];
    while (recv(sock_client, junk, sizeof(junk), MSG_DONTWAIT) > 0);
    
    // 5. CLOSE TOTAL
    close(sock_client);
}