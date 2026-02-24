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

    // 1. Tentukan kuota secara dinamis sesuai config
    if (is_unix) {
        if (config.php_server && strcmp(target, config.php_server) == 0) target_quota = fcgi_pool.php_quota;
        else if (config.rust_server && strcmp(target, config.rust_server) == 0) target_quota = fcgi_pool.rust_quota;
        else if (config.python_server && strcmp(target, config.python_server) == 0) target_quota = fcgi_pool.python_quota;
    } else {
        if (port == config.php_port) target_quota = fcgi_pool.php_quota;
        else if (port == config.rust_port) target_quota = fcgi_pool.rust_quota;
        else if (port == config.python_port) target_quota = fcgi_pool.python_quota;
    }

    // 2. CARI REUSE & HITUNG PEMAKAIAN
    int reuse_idx = -1;
    for (int i = 0; i < fcgi_pool.pool_size; i++) {
        if (fcgi_pool.connections[i].sockfd != -1) {
            bool belongs = false;
            if (is_unix) {
                belongs = (fcgi_pool.connections[i].is_unix && strcmp(fcgi_pool.connections[i].target_path, target) == 0);
            } else {
                belongs = (!fcgi_pool.connections[i].is_unix && fcgi_pool.connections[i].target_port == port);
            }

            if (belongs) {
                if (fcgi_pool.connections[i].in_use) active_for_this_backend++;
                else if (reuse_idx == -1) reuse_idx = i;
            }
        }
    }

    // 3. LOGIKA REUSE
    if (reuse_idx != -1) {
        int error = 0;
        socklen_t len = sizeof(error);
        // Pastikan socket masih hidup sebelum dipakai lagi
        if (getsockopt(fcgi_pool.connections[reuse_idx].sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
            fcgi_pool.connections[reuse_idx].in_use = true;
            pthread_mutex_unlock(&fcgi_pool.lock);
            return fcgi_pool.connections[reuse_idx].sockfd;
        } else {
            // Socket mati, bersihkan
            close(fcgi_pool.connections[reuse_idx].sockfd);
            fcgi_pool.connections[reuse_idx].sockfd = -1;
        }
    }
    
    // Simpan status kuota sebelum lepas lock untuk connect
    bool can_store_in_pool = (active_for_this_backend < target_quota);
    pthread_mutex_unlock(&fcgi_pool.lock);

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