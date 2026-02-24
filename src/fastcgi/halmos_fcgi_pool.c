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

// Instance global pool
HalmosFCGI_Pool fcgi_pool;

/**
 * Inisialisasi pool koneksi secara dinamis sesuai konfigurasi
 */
void halmos_fcgi_pool_init(void) {
    // Panggil fungsi adaptive
    fcgi_pool.pool_size = g_fcgi_pool_size;

    // Alokasi memori secara dinamis
    fcgi_pool.connections = malloc(sizeof(HalmosFCGI_Conn) * fcgi_pool.pool_size);
    
    if (!fcgi_pool.connections) {
        write_log_error("[POOL] FATAL: Memory allocation failed for %d connections", fcgi_pool.pool_size);
        exit(EXIT_FAILURE);
    }

    pthread_mutex_init(&fcgi_pool.lock, NULL);
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        fcgi_pool.connections[i].sockfd = -1;
        fcgi_pool.connections[i].in_use = false;
        fcgi_pool.connections[i].target_port = 0;
        fcgi_pool.connections[i].is_unix = false; // Bersihkan flag
        memset(fcgi_pool.connections[i].target_path, 0, sizeof(fcgi_pool.connections[i].target_path));
    }
    write_log("[POOL] Initialized adaptive connection pool with %d slots", fcgi_pool.pool_size);
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
    pthread_mutex_lock(&fcgi_pool.lock);

    int active_for_this_backend = 0;
    int target_quota = 16; // Default safety net
    // --- PERBAIKAN: Loop untuk mencari koneksi yang BENAR-BENAR sehat ---
    // --- PART 1: CARI REUSE & HITUNG AKTIF ---
    int final_sock = -1;
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        if (fcgi_pool.connections[i].sockfd != -1) {
            bool belongs = is_unix ? 
                (fcgi_pool.connections[i].is_unix && strcmp(fcgi_pool.connections[i].target_path, target) == 0) :
                (!fcgi_pool.connections[i].is_unix && fcgi_pool.connections[i].target_port == port);

            if (belongs) {
                if (fcgi_pool.connections[i].in_use) {
                    active_for_this_backend++;
                } else if (final_sock == -1) {
                    // Validasi kesehatan
                    struct pollfd pfd = { .fd = fcgi_pool.connections[i].sockfd, .events = POLLIN | POLLRDHUP };
                    int ret = poll(&pfd, 1, 0);

                    if (ret > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL))) {
                        close(fcgi_pool.connections[i].sockfd);
                        fcgi_pool.connections[i].sockfd = -1;
                    } else if (ret > 0 && (pfd.revents & POLLIN)) {
                        char buf;
                        if (recv(fcgi_pool.connections[i].sockfd, &buf, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                            close(fcgi_pool.connections[i].sockfd);
                            fcgi_pool.connections[i].sockfd = -1;
                        }
                    } else {
                        // Socket SEHAT, ambil!
                        fcgi_pool.connections[i].in_use = true;
                        final_sock = fcgi_pool.connections[i].sockfd;
                        active_for_this_backend++;
                    }
                }
            }
        }
    }

    bool can_store_in_pool = (active_for_this_backend < target_quota);
    pthread_mutex_unlock(&fcgi_pool.lock);

    // Jika dapat dari pool, selesai.
    if (final_sock != -1) return final_sock;

    // 4. JIKA HARUS CREATE BARU (Diluar Lock agar tidak blocking thread lain)
    int new_sock = -1;
    if (is_unix) {
        new_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (new_sock >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, target, sizeof(addr.sun_path) - 1);
            if (connect(new_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(new_sock);
                new_sock = -1;
            }
        }
    } else {
        new_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (new_sock >= 0) {
            struct timeval timeout = {2, 0}; // 2 detik timeout connect
            setsockopt(new_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, target, &addr.sin_addr);
            if (connect(new_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(new_sock);
                new_sock = -1;
            }
        }
    }
    
    // 5. SIMPAN KE POOL
    if (new_sock != -1) {
        pthread_mutex_lock(&fcgi_pool.lock);
        bool stored = false;
        if (can_store_in_pool) {
            for (int i = 0; i < fcgi_pool.pool_size; i++) {
                if (fcgi_pool.connections[i].sockfd == -1) {
                    fcgi_pool.connections[i].sockfd = new_sock;
                    fcgi_pool.connections[i].in_use = true;
                    fcgi_pool.connections[i].is_unix = is_unix;
                    if (is_unix) strncpy(fcgi_pool.connections[i].target_path, target, 107);
                    else fcgi_pool.connections[i].target_port = port;
                    stored = true;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&fcgi_pool.lock);

        // Gunakan variabel stored untuk logging atau debug
        if (stored) {
            write_log("[POOL] New connection established to backend %s:%d", target, port);
        } else {
            write_log_error("[POOL] Failed to connect to backend %s:%d: %s", target, port, strerror(errno));
        }
    }

    return new_sock;
}

void halmos_fcgi_conn_release(int sockfd) {
    if (sockfd < 0) return;

    pthread_mutex_lock(&fcgi_pool.lock);
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        if (fcgi_pool.connections[i].sockfd == sockfd) {
            
            // 1. Cek kesehatan socket via getsockopt
            int error = 0;
            socklen_t len = sizeof(error);
            int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            
            // 2. Tambahan: Cek apakah socket sebenarnya sudah hangup (POLLRDHUP/EOF)
            // Kadang error=0 tapi socket sudah ditutup sepihak oleh PHP.
            char dummy;
            if (retval == 0 && error == 0) {
                // Peek 1 byte: jika return 0 artinya FIN diterima (EOF)
                if (recv(sockfd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                    error = EPIPE; // Anggap saja pipa putus
                }
            }

            if (retval == 0 && error == 0) {
                // Socket benar-benar sehat
                fcgi_pool.connections[i].in_use = false;
                pthread_mutex_unlock(&fcgi_pool.lock);
                return;
            } else {
                // Socket sakit, buang dari record pool
                fcgi_pool.connections[i].sockfd = -1;
                fcgi_pool.connections[i].in_use = false;
                pthread_mutex_unlock(&fcgi_pool.lock);
                close(sockfd);
                return;
            }
        }
    }
    pthread_mutex_unlock(&fcgi_pool.lock);

    // Jika socket tidak ditemukan di pool (misal karena kuota tadi penuh)
    // Langsung tutup agar FD tidak menumpuk
    close(sockfd);
}