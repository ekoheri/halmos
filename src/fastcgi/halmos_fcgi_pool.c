#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
// Penting untuk POLLRDHUP

#include "halmos_fcgi.h"
#include "halmos_log.h"
#include "halmos_global.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h> // Header untuk fungsi poll()
#include <stdatomic.h> // untuk operasi lock-free atomic_int

// Instance global pool
HalmosFCGI_Pool fcgi_pool;

static int create_backend_socket(const char *target, int port, bool is_unix);

// Helper untuk menentukan index backend
static int get_backend_index(int port) {
    if (port == config.php_port)    return 0;
    if (port == config.rust_port)   return 1;
    if (port == config.python_port) return 2;
    return 0; // Fallback
}

/**
 * Inisialisasi pool koneksi secara dinamis sesuai konfigurasi
 */
void halmos_fcgi_pool_init(void) {
    fcgi_pool.pool_size = g_fcgi_pool_size;
    fcgi_pool.connections = malloc(sizeof(HalmosFCGI_Conn) * fcgi_pool.pool_size);
    
    if (!fcgi_pool.connections) {
        write_log_error("[POOL] FATAL: Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Inisialisasi 3 Papan Skor Atomic (PHP, Rust, Python)
    for (int i = 0; i < 3; i++) {
        atomic_init(&fcgi_pool.active_counts[i], 0);
    }

    pthread_mutex_init(&fcgi_pool.lock, NULL);
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        fcgi_pool.connections[i].sockfd = -1;
        fcgi_pool.connections[i].in_use = false;
    }
    write_log("[POOL] Initialized Multi-Backend Atomic Pool (%d slots)", fcgi_pool.pool_size);
}

void halmos_fcgi_pool_destroy(void) {
    pthread_mutex_lock(&fcgi_pool.lock);
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        if (fcgi_pool.connections[i].sockfd != -1) {
            close(fcgi_pool.connections[i].sockfd);
            fcgi_pool.connections[i].sockfd = -1;
        }
    }
    free(fcgi_pool.connections); // BUANG MEMORI POINTER-NYA
    pthread_mutex_unlock(&fcgi_pool.lock);
    pthread_mutex_destroy(&fcgi_pool.lock);
}

int halmos_fcgi_conn_acquire(const char *target, int port) {
    bool is_unix = (port == 0 || port == -1); 
    int idx = get_backend_index(port);
    int final_sock = -1;

    // --- AMBIL QUOTA DARI HASIL AUDIT ADAPTIVE (Bukan 16 lagi!) ---
    int target_quota;
    if (idx == 0)      target_quota = fcgi_pool.php_quota;
    else if (idx == 1) target_quota = fcgi_pool.rust_quota;
    else               target_quota = fcgi_pool.python_quota;

    // --- BAGIAN 1: TRY REUSE (Cek jatah backend spesifik secara atomic) ---
    if (atomic_load(&fcgi_pool.active_counts[idx]) < target_quota) {
        pthread_mutex_lock(&fcgi_pool.lock);
        for (int i = 0; i < fcgi_pool.pool_size; i++) {
            if (fcgi_pool.connections[i].sockfd != -1 && !fcgi_pool.connections[i].in_use) {
                bool belongs = is_unix ? 
                    (fcgi_pool.connections[i].is_unix && strcmp(fcgi_pool.connections[i].target_path, target) == 0) :
                    (!fcgi_pool.connections[i].is_unix && fcgi_pool.connections[i].target_port == port);

                if (belongs) {
                    struct pollfd pfd = { .fd = fcgi_pool.connections[i].sockfd, .events = POLLIN | POLLRDHUP };
                    if (poll(&pfd, 1, 0) == 0) {
                        fcgi_pool.connections[i].in_use = true;
                        final_sock = fcgi_pool.connections[i].sockfd;
                        atomic_fetch_add(&fcgi_pool.active_counts[idx], 1); // Tambah skor backend idx
                        break;
                    } else {
                        close(fcgi_pool.connections[i].sockfd);
                        fcgi_pool.connections[i].sockfd = -1;
                    }
                }
            }
        }
        pthread_mutex_unlock(&fcgi_pool.lock);
    }

    // --- BAGIAN 2: CREATE BARU JIKA PERLU ---
    if (final_sock == -1) {
        final_sock = create_backend_socket(target, port, is_unix);
        if (final_sock != -1) {
            bool stored = false;
            pthread_mutex_lock(&fcgi_pool.lock);
            
            // Double check quota backend ini
            if (atomic_load(&fcgi_pool.active_counts[idx]) < target_quota) {
                for (int i = 0; i < fcgi_pool.pool_size; i++) {
                    if (fcgi_pool.connections[i].sockfd == -1) {
                        fcgi_pool.connections[i].sockfd = final_sock;
                        fcgi_pool.connections[i].in_use = true;
                        fcgi_pool.connections[i].is_unix = is_unix;
                        fcgi_pool.connections[i].target_port = port;
                        if (is_unix) strncpy(fcgi_pool.connections[i].target_path, target, 107);
                        
                        atomic_fetch_add(&fcgi_pool.active_counts[idx], 1);
                        stored = true;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&fcgi_pool.lock);
            write_log(stored ? "[POOL] Pooled new connection for port %d" : "[POOL] Bypass pool (Full) for port %d", port);
        }
    }
    return final_sock;
}

void halmos_fcgi_conn_release(int sockfd) {
    if (sockfd < 0) return;

    pthread_mutex_lock(&fcgi_pool.lock);
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        if (fcgi_pool.connections[i].sockfd == sockfd) {
            
            // Identifikasi ini punya siapa (PHP/Rust/Python)
            int idx = get_backend_index(fcgi_pool.connections[i].target_port);
            
            // Cek kesehatan (logic kamu sudah bagus)
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            char dummy;
            bool healthy = (error == 0 && recv(sockfd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT) != 0);

            if (healthy) {
                fcgi_pool.connections[i].in_use = false;
            } else {
                fcgi_pool.connections[i].sockfd = -1;
                fcgi_pool.connections[i].in_use = false;
                close(sockfd);
            }

            // Kurangi skor backend spesifik ini
            atomic_fetch_sub(&fcgi_pool.active_counts[idx], 1);
            
            pthread_mutex_unlock(&fcgi_pool.lock);
            return;
        }
    }
    pthread_mutex_unlock(&fcgi_pool.lock);
    close(sockfd);
}

/*
FUNGSI HELPER
*/

int create_backend_socket(const char *target, int port, bool is_unix) {
    int sock = -1;
    if (is_unix) {
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_un addr = { .sun_family = AF_UNIX };
            strncpy(addr.sun_path, target, sizeof(addr.sun_path) - 1);
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock); sock = -1;
            }
        }
    } else {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct timeval timeout = {2, 0};
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
            inet_pton(AF_INET, target, &addr.sin_addr);
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock); sock = -1;
            }
        }
    }
    return sock;
}
