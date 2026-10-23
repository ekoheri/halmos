#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_fcgi_upstream.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdbool.h>

// Definisi instance global upstream manager
FCGI_Upstream fcgi_upstream;

/*
[TIANG UTAMA: IDENTITY MAPPER]
Menghubungkan port fisik atau path Unix yang sedang aktif dengan ID grup (0: PHP, 1: Rust, 2: Python).
*/
static int get_backend_index(const char *target, int port) {
    bool is_unix = (port == 0 || port == -1);

    // 1. Cek Grup PHP
    for (int i = 0; i < config.php.node_count; i++) {
        if (is_unix) {
            if (target && strcmp(config.php.ips[i], target) == 0) return 0;
        } else {
            if (config.php.ports[i] == port) return 0;
        }
    }

    // 2. Cek Grup Rust
    for (int i = 0; i < config.rust.node_count; i++) {
        if (is_unix) {
            if (target && strcmp(config.rust.ips[i], target) == 0) return 1;
        } else {
            if (config.rust.ports[i] == port) return 1;
        }
    }

    // 3. Cek Grup Python
    for (int i = 0; i < config.python.node_count; i++) {
        if (is_unix) {
            if (target && strcmp(config.python.ips[i], target) == 0) return 2;
        } else {
            if (config.python.ports[i] == port) return 2;
        }
    }

    return 0; // Fallback default ke PHP
}

/*
[TIANG UTAMA: SOCKET CREATION]
Membuat socket TCP atau Unix Domain baru dengan mode non-blocking (EINPROGRESS friendly).
*/
static int create_backend_socket(const char *target, int port, bool is_unix) {
    int sock = -1;

    if (is_unix) {
        sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock >= 0) {
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(sock);
                return -1;
            }

            struct sockaddr_un addr = { .sun_family = AF_UNIX };
            if (target) {
                strncpy(addr.sun_path, target, sizeof(addr.sun_path) - 1);
                addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
            }

            int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
            if (res < 0 && errno != EINPROGRESS) {
                close(sock);
                sock = -1;
            }
        }
    } else {
        sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock >= 0) {
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(sock);
                return -1;
            }

            struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
            if (target) {
                inet_pton(AF_INET, target, &addr.sin_addr);
            }

            int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
            if (res < 0 && errno != EINPROGRESS) {
                write_log_error_code(ERR_FCGI_BACKEND_SOCK, target ? target : "0.0.0.0", port);
                close(sock);
                sock = -1;
            }
        }
    }

    return sock;
}

bool fcgi_upstream_start(void) {
    fcgi_upstream.slots = (g_fcgi_upstream_slots > 0) ? g_fcgi_upstream_slots : 128;
    fcgi_upstream.connections = malloc(sizeof(FCGI_Conn) * fcgi_upstream.slots);

    if (!fcgi_upstream.connections) {
        write_log_error_code(ERR_FCGI_UPSTREAM_MEM);
        return false;
    }

    // Inisialisasi 3 Papan Skor Atomic (PHP, Rust, Python)
    for (int i = 0; i < 3; i++) {
        atomic_init(&fcgi_upstream.active_counts[i], 0);
    }

    // Inisialisasi Round-Robin Next Index Atomic per Grup
    atomic_init(&fcgi_upstream.php_group.next_idx, 0);
    atomic_init(&fcgi_upstream.rust_group.next_idx, 0);
    atomic_init(&fcgi_upstream.python_group.next_idx, 0);

    // Set jumlah node dari config global jika tersedia
    fcgi_upstream.php_group.node_count = config.php.node_count > 0 ? config.php.node_count : 1;
    fcgi_upstream.rust_group.node_count = config.rust.node_count > 0 ? config.rust.node_count : 1;
    fcgi_upstream.python_group.node_count = config.python.node_count > 0 ? config.python.node_count : 1;

    // Set kuota default awal
    fcgi_upstream.php_quota = 32;
    fcgi_upstream.rust_quota = 32;
    fcgi_upstream.python_quota = 32;
    fcgi_upstream.current_idle_count = fcgi_upstream.slots;

    pthread_mutex_init(&fcgi_upstream.lock, NULL);
    for (int i = 0; i < fcgi_upstream.slots; i++) {
        fcgi_upstream.connections[i].sockfd = -1;
        fcgi_upstream.connections[i].in_use = false;
        fcgi_upstream.connections[i].target_port = 0;
        fcgi_upstream.connections[i].target_path[0] = '\0';
        fcgi_upstream.connections[i].is_unix = false;
    }
    return true;
}

void fcgi_upstream_stop(void) {
    pthread_mutex_lock(&fcgi_upstream.lock);
    for (int i = 0; i < fcgi_upstream.slots; i++) {
        if (fcgi_upstream.connections[i].sockfd != -1) {
            close(fcgi_upstream.connections[i].sockfd);
            fcgi_upstream.connections[i].sockfd = -1;
        }
    }
    free(fcgi_upstream.connections);
    fcgi_upstream.connections = NULL;
    pthread_mutex_unlock(&fcgi_upstream.lock);
    pthread_mutex_destroy(&fcgi_upstream.lock);
    write_log("[UPSTREAM] Upstream manager destroyed successfully.");
}

int fcgi_upstream_acquire(const char *target, int port) {
    bool is_unix = (port == 0 || port == -1);
    int idx = get_backend_index(target, port);
    int final_sock = -1;

    // Ambil jatah kuota adaptif berdasarkan grup backend
    int target_quota;
    if (idx == 0)      target_quota = fcgi_upstream.php_quota;
    else if (idx == 1) target_quota = fcgi_upstream.rust_quota;
    else               target_quota = fcgi_upstream.python_quota;

    // --- BAGIAN 1: TRY REUSE (Cek jatah backend spesifik secara atomic & health check) ---
    if (atomic_load(&fcgi_upstream.active_counts[idx]) < target_quota) {
        pthread_mutex_lock(&fcgi_upstream.lock);
        for (int i = 0; i < fcgi_upstream.slots; i++) {
            if (fcgi_upstream.connections[i].sockfd != -1 && !fcgi_upstream.connections[i].in_use) {
                bool belongs = is_unix ? 
                    (fcgi_upstream.connections[i].is_unix && target && strcmp(fcgi_upstream.connections[i].target_path, target) == 0) :
                    (!fcgi_upstream.connections[i].is_unix && fcgi_upstream.connections[i].target_port == port);

                if (belongs) {
                    /*
                    [TIANG UTAMA: CONNECTION HEALTH - struct pollfd pfd]
                    POLLRDHUP mendeteksi jika backend (FPM) memutus koneksi sepihak.
                    */
                    struct pollfd pfd = { .fd = fcgi_upstream.connections[i].sockfd, .events = POLLIN | POLLRDHUP };
                    if (poll(&pfd, 1, 0) == 0) {
                        fcgi_upstream.connections[i].in_use = true;
                        final_sock = fcgi_upstream.connections[i].sockfd;
                        atomic_fetch_add(&fcgi_upstream.active_counts[idx], 1);
                        fcgi_upstream.current_idle_count--;
                        break;
                    } else {
                        close(fcgi_upstream.connections[i].sockfd);
                        fcgi_upstream.connections[i].sockfd = -1;
                    }
                }
            }
        }
        pthread_mutex_unlock(&fcgi_upstream.lock);
    }

    // --- BAGIAN 2: CREATE BARU JIKA PERLU ---
    if (final_sock == -1) {
        final_sock = create_backend_socket(target, port, is_unix);
        if (final_sock != -1) {
            pthread_mutex_lock(&fcgi_upstream.lock);
            
            if (atomic_load(&fcgi_upstream.active_counts[idx]) < target_quota) {
                for (int i = 0; i < fcgi_upstream.slots; i++) {
                    if (fcgi_upstream.connections[i].sockfd == -1) {
                        fcgi_upstream.connections[i].sockfd = final_sock;
                        fcgi_upstream.connections[i].in_use = true;
                        fcgi_upstream.connections[i].is_unix = is_unix;
                        fcgi_upstream.connections[i].target_port = port;
                        if (is_unix && target) {
                            strncpy(fcgi_upstream.connections[i].target_path, target, sizeof(fcgi_upstream.connections[i].target_path) - 1);
                            fcgi_upstream.connections[i].target_path[sizeof(fcgi_upstream.connections[i].target_path) - 1] = '\0';
                        }
                        
                        atomic_fetch_add(&fcgi_upstream.active_counts[idx], 1);
                        fcgi_upstream.current_idle_count--;
                        break;
                    }
                }
            } else {
                close(final_sock);
                final_sock = -1;
            }
            pthread_mutex_unlock(&fcgi_upstream.lock);
        }
    }

    return final_sock;
}

void fcgi_upstream_release(int sockfd) {
    if (sockfd < 0) return;

    pthread_mutex_lock(&fcgi_upstream.lock);
    for (int i = 0; i < fcgi_upstream.slots; i++) {
        if (fcgi_upstream.connections[i].sockfd == sockfd) {
            int idx = get_backend_index(
                fcgi_upstream.connections[i].is_unix ? fcgi_upstream.connections[i].target_path : NULL, 
                fcgi_upstream.connections[i].target_port
            );

            // Validasi kesehatan socket sebelum dikembalikan ke slot
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            
            char dummy;
            bool healthy = (error == 0 && recv(sockfd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT) != 0);

            if (healthy) {
                fcgi_upstream.connections[i].in_use = false;
            } else {
                write_log_warn_code(WARN_FCGI_BACKEND_DEAD, sockfd);
                close(sockfd);
                fcgi_upstream.connections[i].sockfd = -1;
                fcgi_upstream.connections[i].in_use = false;
            }

            // Kurangi skor aktif atomic backend terkait
            atomic_fetch_sub(&fcgi_upstream.active_counts[idx], 1);
            fcgi_upstream.current_idle_count++;
            
            pthread_mutex_unlock(&fcgi_upstream.lock);
            return;
        }
    }
    pthread_mutex_unlock(&fcgi_upstream.lock);
    close(sockfd);
}

int fcgi_upstream_select_node(RequestHeader *req, int backend_type, const char **out_ip, int *out_port, bool *out_is_unix) {
    UpstreamGroup *live_group;
    BackendGroup  *cfg_group;
    VHostEntry *vh = req ? req->vhost_context : NULL;  

    // 1. Mapping Grup berdasarkan Tipe Backend (0: PHP, 1: Rust, 2: Python)
    if (backend_type == 0) {
        live_group = &fcgi_upstream.php_group;
        cfg_group  = (vh && vh->php.node_count > 0) ? &vh->php : &config.php;
    } else if (backend_type == 1) {
        live_group = &fcgi_upstream.rust_group;
        cfg_group  = (vh && vh->rust.node_count > 0) ? &vh->rust : &config.rust;
    } else {
        live_group = &fcgi_upstream.python_group;
        cfg_group  = (vh && vh->python.node_count > 0) ? &vh->python : &config.python;
    }

    if (cfg_group->node_count <= 0) {
        return -1; // Tidak ada node tersedia
    }

    // 2. Eksekusi Load Balancing (IP Hash vs Round-Robin)
    int idx = 0;
    if (strcmp(cfg_group->lb_strategy, "ip_hash") == 0 && req && req->client_ip[0] != '\0') {
        // IP Hash sederhana untuk Sticky Session menggunakan string array client_ip
        unsigned int hash = 5381;
        const char *ip = req->client_ip;
        int c;
        while ((c = *ip++)) hash = ((hash << 5) + hash) + c;
        idx = hash % cfg_group->node_count;
    } else {
        // Round-Robin global per backend group
        idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    }

    // 3. Output hasil seleksi
    *out_ip = cfg_group->ips[idx];
    *out_port = cfg_group->ports[idx];
    
    // Tentukan apakah menggunakan Unix Domain Socket (port 0 atau -1)
    *out_is_unix = (*out_port == 0 || *out_port == -1);

    return backend_type;
}