#include "halmos_ipc_bridge.h"
#include "halmos_websocket.h" // Untuk akses registry & send_ws_frame
#include "halmos_log.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

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
    
    listen(bridge_fd, 16);
    set_nonblocking_bridge(bridge_fd);

    write_log("[IPC] Bridge established at %s", path);
    return bridge_fd;
}

void handle_bridge_request(int bridge_fd) {
    int client_sock = accept(bridge_fd, NULL, NULL);
    if (client_sock < 0) return;

    char buffer[8192]; 
    ssize_t n = read(client_sock, buffer, sizeof(buffer) - 1);
    
    if (n > 0) {
        buffer[n] = '\0';

        /* LOGIKA ROUTING SESUAI PROTOKOL LU:
           Di sini lu bisa pakai parser JSON (cJSON) untuk ambil:
           - header.src
           - header.type
           - header.dst (Ani, Budi, atau "BROADCAST")
        */

        // Contoh simulasi logic:
        // 1. Cek apakah src mengandung "HALMOS_"
        // 2. Jika valid, cari FD si "dst" di halmos_websocket_registry
        // 3. Panggil halmos_ws_send_message(target_fd, payload)

        write_log("[IPC] Internal command received: %s", buffer);
        
        // Panggil fungsi distribusi (Kita asumsikan lu punya ini di halmos_websocket.c)
        halmos_ws_internal_dispatch(buffer); 
    }

    close(client_sock);
}