/*
IPC : Inter-Process Communication
Adalah mekanisme atau cara supaya satu program (proses) bisa ngobrol, 
tukar data, atau kasih instruksi ke program lainnya yang lagi jalan di sistem operasi yang sama.
Di projek lu ini, IPC adalah "jembatan" yang lu bikin antara PHP dan Halmos (C).
*/

#include "halmos_ws_ipc.h"
#include "halmos_ws_system.h" // Untuk akses registry & send_ws_frame
#include "halmos_log.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>  // <--- Untuk CHMOD
#include <errno.h>

// global scope di halmos_ws_ipc untuk buffer
static char ipc_buffer[65536];

// Fungsi pembantu set non-blocking
static void set_nonblocking_bridge(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int setup_uds_bridge(const char *path) {
    int bridge_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bridge_fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path); // Bersihkan sisa socket lama
    if (bind(bridge_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(bridge_fd);
        return -1;
    }

    // Ubah permission file socket agar bisa diakses oleh user www-data (PHP)
    if (chmod(path, 0666) < 0) {
        write_log_error("[IPC] Failed to change permissions on %s", path);
    }
    
    //SOMAXCONN adalah konstanta sistem (biasanya 128 atau 4096 tergantung konfigurasi OS) 
    //yang berarti "kasih limit maksimal yang diizinkan sistem".
    listen(bridge_fd, SOMAXCONN);
    set_nonblocking_bridge(bridge_fd);

    write_log("[IPC] Bridge established at %s", path);
    return bridge_fd;
}

void handle_bridge_request(int bridge_fd) {
    while (1) {
        int client_sock = accept(bridge_fd, NULL, NULL);
        if (client_sock < 0) {
            // EAGAIN di sini berarti semua antrean 'accept' sudah habis ditarik
            if (errno == EAGAIN || errno == EWOULDBLOCK) break; 
            return;
        }

        // [Security Check UID tetap di sini...]

        // SET NON-BLOCKING pada client_sock
        set_nonblocking_bridge(client_sock);

        ssize_t total_received = 0;
        int retry_count = 0;

        while (total_received < (ssize_t)(sizeof(ipc_buffer) - 1)) {
            ssize_t n = read(client_sock, ipc_buffer + total_received, (ssize_t)sizeof(ipc_buffer) - 1 - total_received);

            if (n > 0) {
                total_received += n;
                // Cek apakah pesan sudah berakhir dengan newline
                if (ipc_buffer[total_received - 1] == '\n') break;
            } 
            else if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Data belum siap di kernel. Karena ini UDS (lokal), 
                    // kita bisa kasih toleransi retry kecil atau balik ke loop utama.
                    if (retry_count++ < 1000) continue; 
                    else break;
                }
                if (errno == EINTR) continue;
                break;
            } 
            else { // n == 0 (Client tutup koneksi)
                break;
            }
        }

        if (total_received > 0) {
            ipc_buffer[total_received] = '\0';
            // Bersihkan \n \r
            for (ssize_t i = total_received - 1; i >= 0 && (ipc_buffer[i] == '\n' || ipc_buffer[i] == '\r'); i--) {
                ipc_buffer[i] = '\0';
            }
            ws_system_internal_dispatch(ipc_buffer);
        }

        close(client_sock);
    }
}

