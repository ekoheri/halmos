#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <poll.h>

/* ------------------------------------------- */
#include <unistd.h>      // Buat close()
#include <netinet/in.h>  // Buat IPPROTO_TCP
#include <netinet/tcp.h> // Buat TCP_CORK
/* ------------------------------------------- */

#include "http1_handler.h"
#include "http1_response.h"
#include "fs_handler.h"
#include "config.h"
#include "http_utils.h"
#include "log.h"

extern Config config;


void handle_static_request(int sock_client, RequestHeader *req) {
    const char *active_root = get_active_root(req->host);
    char *safe_path = sanitize_path(active_root, req->uri);

    write_log("[DEBUG] Full Path: %s", safe_path);

    if (!safe_path) {
        //printf("[DEBUG] Error Stat: %s (File mungkin tidak ada)\n", safe_file_path);
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        return;
    }

    struct stat st;
    if (stat(safe_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>", req->is_keep_alive);
        free(safe_path); return;
    }

    int fd = open(safe_path, O_RDONLY);
    if (fd != -1) {
        int state = 1;
        setsockopt(sock_client, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

        char header[1024];
        int h_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
            "Server: Halmos-Core\r\nConnection: %s\r\n\r\n",
            get_mime_type(req->uri), st.st_size, req->is_keep_alive ? "keep-alive" : "close");
        
        send(sock_client, header, h_len, 0);

        off_t offset = 0;
        size_t remaining = st.st_size;
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            
            if (sent > 0) {
                remaining -= (size_t)sent;
                //total_sent += (size_t)sent;
                continue;
            }

            if (sent < 0) {
                if (errno == EINTR) continue;
                
                // JIKA BUFFER PENUH (EAGAIN / EWOULDBLOCK)
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Tunggu sampai socket siap (writable) selama maksimal 5 detik
                    struct pollfd pfd;
                    pfd.fd = sock_client;
                    pfd.events = POLLOUT;
                    
                    int ret = poll(&pfd, 1, 5000); // timeout 5000ms
                    if (ret > 0 && (pfd.revents & POLLOUT)) {
                        continue; // Socket sudah lega, hajar lagi!
                    } else {
                        //printf("[DEBUG] Timeout/Error nunggu buffer lega\n");
                        break; 
                    }
                }
                
                //printf("[DEBUG] Sendfile Error: %s\n", strerror(errno));
                break;
            }
            if (sent == 0) break; // Client cabut
        }

        // D. Cabut CORK: Paksa kernel kirim paket terakhir (Zero-Latency Finish)
        // printf("[DEBUG] Total Body terkirim: %zu/%ld bytes\n", total_sent, st.st_size);
        state = 0;
        setsockopt(sock_client, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

        close(fd);
    }
    free(safe_path);
}