/*
 * IPC : Inter-Process Communication (Unix Domain Socket Bridge)
 * Jembatan komunikasi berkecepatan tinggi antara PHP/Backend dengan Halmos Engine (C).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Diperlukan untuk accept4() dan flag SOCK_CLOEXEC/SOCK_NONBLOCK
#endif

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
#include <poll.h>      // Wajib ada untuk fungsi poll()

// Set non-blocking flags safely with complete error checking
static int set_nonblocking_bridge(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
    return 0;
}

int setup_uds_bridge(const char *path) {
    // SOCK_CLOEXEC prevents fd leaks across fork/exec calls
    int bridge_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (bridge_fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    // Safeguard: Only unlink existing files if they are genuine UNIX domain sockets
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISSOCK(st.st_mode)) {
            unlink(path);
        } else {
            write_log_error("[IPC] File %s exists and is NOT a socket. Aborting.", path);
            close(bridge_fd);
            return -1;
        }
    }

    if (bind(bridge_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(bridge_fd);
        return -1;
    }

    // 0660 grants RW permissions to owner and group (e.g., www-data) while blocking world access
    if (chmod(path, 0660) < 0) {
        write_log_error("[IPC] Failed to change permissions on %s", path);
    }
    
    // Explicit return checking prevents leaving partially bound sockets open on failure
    if (listen(bridge_fd, SOMAXCONN) < 0) {
        write_log_error("[IPC] Listen failed on %s: %s", path, strerror(errno));
        close(bridge_fd);
        unlink(path);
        return -1;
    }

    if (set_nonblocking_bridge(bridge_fd) < 0) {
        write_log_error("[IPC] Failed to set non-blocking on bridge_fd");
        close(bridge_fd);
        unlink(path);
        return -1;
    }

    write_log("[IPC] Bridge established at %s", path);
    return bridge_fd;
}

void handle_bridge_request(int bridge_fd) {
    // Thread-safe local stack buffer to prevent race conditions during high IPC load
    char local_ipc_buffer[65536];

    while (1) {
        // accept4() avoids extra fcntl() calls and atomically sets NONBLOCK and CLOEXEC on accepted sockets
        int client_sock = accept4(bridge_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break; 
            return;
        }

        ssize_t total_received = 0;
        int retry_count = 0;
        const int max_retries = 5;

        while (total_received < (ssize_t)(sizeof(local_ipc_buffer) - 1)) {
            ssize_t n = read(client_sock, local_ipc_buffer + total_received, 
                             (ssize_t)sizeof(local_ipc_buffer) - 1 - total_received);

            if (n > 0) {
                total_received += n;
                retry_count = 0;
                
                if (total_received > 0 && local_ipc_buffer[total_received - 1] == '\n') {
                    break;
                }
            } 
            else if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd = { .fd = client_sock, .events = POLLIN };
                    int poll_res = poll(&pfd, 1, 10); 
                    
                    if (poll_res > 0) {
                        continue;
                    } else {
                        if (retry_count++ < max_retries) continue;
                        else break;
                    }
                }
                if (errno == EINTR) continue;
                break;
            } 
            else { 
                break;
            }
        }

        if (total_received > 0) {
            local_ipc_buffer[total_received] = '\0';
            
            ssize_t i = total_received - 1;
            while (i >= 0 && (local_ipc_buffer[i] == '\n' || local_ipc_buffer[i] == '\r')) {
                local_ipc_buffer[i] = '\0';
                i--;
            }
            
            // Direct O(1) null check avoids redundant memory scan via strlen()
            if (local_ipc_buffer[0] != '\0') {
                ws_system_internal_dispatch(local_ipc_buffer);
            }
        }

        close(client_sock);
    }
}
