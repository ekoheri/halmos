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
    
    listen(bridge_fd, 16);
    set_nonblocking_bridge(bridge_fd);

    write_log("[IPC] Bridge established at %s", path);
    return bridge_fd;
}

void handle_bridge_request(int bridge_fd) {
    // 1. Loop Accept sampai habis (Poin #1 lu)
    while (1) {
        struct ucred cred;
        socklen_t cred_len = sizeof(struct ucred);
        
        int client_sock = accept(bridge_fd, NULL, NULL);

        if (client_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break; // Antrean habis
            return;
        }

        // 2. Security Check: Validasi UID (Poin #3 lu)
        if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0) {
            // Misalnya: Hanya ijinkan root (0) atau www-data (biasanya 33)
            if (cred.uid != 0 && cred.uid != 33) { 
                write_log_error("[IPC-SECURITY] Unauthorized UID %d tried to connect!", cred.uid);
                close(client_sock);
                continue;
            }
        }

        // 3. Set Non-blocking untuk client_sock (Poin #2 lu)
        set_nonblocking_bridge(client_sock);

        char buffer[8192];
        ssize_t n = read(client_sock, buffer, sizeof(buffer) - 1);

        if (n > 0) {
            buffer[n] = '\0';
            // write_log("[IPC] Processing: %s", buffer);
            //fprintf(stderr, "\n[DEBUG-BRIDGE] Data masuk: %s\n", buffer);
            
            // Dispatching ke logika JSON lu
            ws_system_internal_dispatch(buffer);
        } 
        /*else {
            fprintf(stderr, "[DEBUG-BRIDGE] Read error/empty. n=%ld\n", (long)n);
        }*/

        close(client_sock);
    }
}