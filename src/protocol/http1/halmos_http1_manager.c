#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_http1_header.h"
#include "halmos_http1_parser.h"
#include "halmos_http1_response.h"
#include "halmos_http_vhost.h"
#include "halmos_http_utils.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"
#include "halmos_ws_system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>    // Buat memset, strstr
#include <unistd.h>    // Buat usleep, read, close
#include <sys/socket.h> // Buat recv, send
#include <errno.h>
#include <stdbool.h>   // Buat tipe data bool
#include <openssl/ssl.h> // Pastikan ini ada kalau Boss panggil SSL_read/write
#include <poll.h>
#include <sys/stat.h>  // Biar kenal 'struct stat' dan 'stat()'
#include <fcntl.h>     // Biar kenal 'open()' dan 'O_RDONLY'
#include <netinet/in.h>  // <--- TAMBAHKAN INI
#include <arpa/inet.h>   // <--- TAMBAHKAN INI

/* --- FUNGSI INTERNAL (STATIC) --- */

/**
 * halmos_recv: Wrapper cerdas untuk baca data.
 * Di sinilah "Dapur Dekripsi" berada.
 */
static ssize_t halmos_recv(int fd, void *buf, size_t len, bool is_tls) {
    if (is_tls) {
        SSL *ssl = ssl_get_for_fd(fd);
        if (!ssl) return -1;
        // SSL_read melakukan dekripsi internal sebelum masuk ke buf
        return SSL_read(ssl, buf, (int)len);
    }
    return recv(fd, buf, len, 0);
}

/**
 * Tunggu data dengan Poll agar tidak memakan CPU (Busy-wait)
 */
static bool wait_for_data(int fd, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    return poll(&pfd, 1, timeout_ms) > 0;
}

/**
 * Geser semua pointer di req_header setelah buffer di-realloc.
 * Menjaga agar Zero-Copy parser tidak crash.
 */
static void update_header_pointers(RequestHeader *req, ptrdiff_t diff) {
    if (req->uri)          req->uri += diff;
    if (req->directory)    req->directory += diff;
    if (req->query_string) req->query_string += diff;
    if (req->host)         req->host += diff;
    if (req->content_type) req->content_type += diff;
    if (req->cookie_data)  req->cookie_data += diff;
    if (req->body_data)    req->body_data = (void*)((char*)req->body_data + diff);
    if (req->path_info)    req->path_info += diff;
}

/**
 * Fungsi khusus menarik Header sampai ketemu \r\n\r\n
 */

static ssize_t recv_until_header_end(int sock, char *buf, size_t limit, bool is_tls) {
    ssize_t total = 0;
    int timeout_ms = 3000; 
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);

    //fprintf(stderr, "[RECV-START] FD %d: Mulai nunggu header...\n", sock);

    while (total < (ssize_t)limit - 1) {
        ssize_t n = halmos_recv(sock, buf + total, limit - total - 1, is_tls);
        
        if (n > 0) {
            total += n;
            buf[total] = '\0'; 
            
            // CCTV: Print potongan data yang baru masuk
            //fprintf(stderr, "[RECV-DATA] FD %d: Dapet %zd bytes. Total skrg: %zd\n", sock, n, total);
            
            if (strstr(buf, "\r\n\r\n")) {
                //fprintf(stderr, "[RECV-OK] FD %d: Ketemu \\r\\n\\r\\n! Header lengkap.\n", sock);
                return total; 
            }
            continue; 
        } 
        
        if (n < 0) {
            bool retry_it = false;
            if (is_tls) {
                int err_code = SSL_get_error(ssl_get_for_fd(sock), (int)n);
                if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) retry_it = true;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                retry_it = true;
            }

            if (retry_it) {
                gettimeofday(&current_time, NULL);
                long elapsed = (current_time.tv_sec - start_time.tv_sec) * 1000 + 
                               (current_time.tv_usec - start_time.tv_usec) / 1000;
                
                if (elapsed >= timeout_ms) {
                    // CCTV: Kalau timeout, kita intip isi buffer terakhirnya apa
                    //fprintf(stderr, "[RECV-TIMEOUT] FD %d: %ld ms berlalu. Buffer terakhir: [%.20s...]\n", 
                    //        sock, elapsed, total > 0 ? buf : "KOSONG");
                    break;
                }

                struct pollfd pfd = { .fd = sock, .events = POLLIN };
                int res = poll(&pfd, 1, 100); 
                if (res > 0) continue; 
                if (res == 0) continue; 
                //fprintf(stderr, "[RECV-ERR] FD %d: Poll error res=%d\n", sock, res);
                break; 
            }
            //fprintf(stderr, "[RECV-ERR] FD %d: recv error n=%zd, errno=%d\n", sock, n, errno);
            break; 
        } 
        
        if (n == 0) {
            //fprintf(stderr, "[RECV-CLOSED] FD %d: Client tutup koneksi.\n", sock);
            break; 
        }
    }

    //fprintf(stderr, "[RECV-FAIL] FD %d: Gagal dapet header lengkap. Total data: %zd\n", sock, total);
    return -1; 
}

/**
 * Fungsi khusus menarik sisa Body berdasarkan Content-Length
 */
static bool recv_http_body(int sock, RequestHeader *req, char **buf_ptr, size_t *limit, bool is_tls) {
    size_t header_len = (char*)req->body_data - *buf_ptr;
    size_t total_needed = header_len + req->content_length;

    // Ekspansi buffer jika body lebih besar dari buffer awal
    if (total_needed > *limit) {
        char *new_buf = realloc(*buf_ptr, total_needed + 1);
        if (!new_buf) return false;
        
        update_header_pointers(req, new_buf - *buf_ptr);
        *buf_ptr = new_buf;
        *limit = total_needed + 1;
    }

    char *ptr = (char *)req->body_data + req->body_length;
    size_t to_recv = req->content_length - req->body_length;
    
    while (to_recv > 0) {
        ssize_t n = halmos_recv(sock, ptr, to_recv, is_tls);
        if (n > 0) {
            ptr += n; to_recv -= n; req->body_length += n;
        } else {
            if (n < 0 && wait_for_data(sock, 100)) continue;
            return false; 
        }
    }
    return true;
}

/* --- FUNGSI UTAMA (PUBLIC) --- */

int http1_manager_session(int sock_client, bool is_tls) {
    // --- [TIANG IDENTITAS: AMBIL IP CLIENT SEKALI SAJA] ---
    char current_client_ip[46] = "0.0.0.0"; 
    
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getpeername(sock_client, (struct sockaddr*)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &s->sin_addr, current_client_ip, sizeof(current_client_ip));
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &s->sin6_addr, current_client_ip, sizeof(current_client_ip));
        }
    }
    // ------------------------------------------------------
    // CCTV 1: Cek apakah sesi dimulai
    //fprintf(stderr, "[DEBUG] Sesi dimulai. FD: %d, TLS: %s\n", sock_client, is_tls ? "YES" : "NO");
    //fprintf(stderr, "[DEBUG-MANAGER] FD %d: Memulai sesi HTTP1. TLS=%d\n", sock_client, is_tls);
    int keep_alive = 1;
    size_t buf_limit = (config.request_buffer_size > 0) ? config.request_buffer_size : 8192;
    char *buffer = malloc(buf_limit);
    if (!buffer) {
        //fprintf(stderr, "[DEBUG-MANAGER] FD %d: Gagal alokasi buffer!\n", sock_client);
        return 0;
    }

    while (keep_alive) {
        RequestHeader req;
        memset(&req, 0, sizeof(RequestHeader));
        memcpy(req.client_ip, current_client_ip, sizeof(req.client_ip));
        req.is_tls = is_tls; // Simpan status "KTP" TLS

        // 1. Tarik Header
        //fprintf(stderr, "[DEBUG-MANAGER] FD %d: Menunggu header selesai...\n", sock_client);
        ssize_t received = recv_until_header_end(sock_client, buffer, buf_limit, is_tls);
        // CCTV 2: Cek data yang masuk
        //fprintf(stderr, "[DEBUG] Header diterima: %ld bytes\n", received);
        
        if (received <= 0) {
            //fprintf(stderr, "[DEBUG-MANAGER] FD %d: recv_until_header_end dapet %zd. Putus!\n", sock_client, received);
            break;
        }

        //fprintf(stderr, "[DEBUG-MANAGER] FD %d: Header OK (%zd bytes). Cek WS Upgrade...\n", sock_client, received);
        // 2. Parsing (Data sudah didekripsi oleh halmos_recv)
        if (!http1_parser_parse_header(buffer, received, &req) || !req.is_valid) {
            //fprintf(stderr, "[DEBUG] Parser GAGAL! Mengirim 400 Bad Request...\n");
            http1_response_send_mem(sock_client, 400, "Bad Request", "400 Bad Request", is_tls);
            http1_parser_free_memory(&req);
            break;
        }

        // --- [ PASANG RATE LIMIT DI SINI JIKA STATUS DI CONFIG = true] ---
        if(config.rate_limit_enabled == true) {
            // Gunakan limit dari config jika ada, atau default (misal: 50 req/sec)
            int limit = (config.max_requests_per_sec > 0) ? config.max_requests_per_sec : 50;
            
            if (!sec_traffic_is_request_allowed(req.client_ip, limit)) {
                // Kirim status 429 Too Many Requests
                http1_response_send_mem(sock_client, 429, "Too Many Requests", 
                                        "<h1>429 Too Many Requests</h1><p>Slow down, buddy.</p>", is_tls);
                http1_parser_free_memory(&req);
                
                // Opsional: Langsung putus koneksi (break) atau lanjut (keep_alive = 0)
                // Untuk pertahanan DoS, lebih baik langsung putus koneksi.
                break; 
            }
        }
        // -------------------------------------

        if (ws_is_upgrade_request(&req)) {
            //fprintf(stderr, "[DEBUG-MANAGER] FD %d: POSITIF WEBSOCKET UPGRADE!\n", sock_client);
            if (ws_upgrade_handshake(sock_client, &req) == 0) {
                //fprintf(stderr, "[DEBUG-MANAGER] FD %d: Handshake Sukses. Pindah ke WS Mode.\n", sock_client);
                halmos_set_websocket_fd(sock_client, true); // NYALAKAN SAKLAR
                http1_parser_free_memory(&req);
                free(buffer);
                return 1; // Rearm epoll, tunggu frame WS pertama
            }
        }
        // CCTV 3: Kalau sampai sini, berarti sukses masuk ke routing
        //fprintf(stderr, "[DEBUG] Parser Sukses. Mengarahkan ke routing...\n");

        // 3. Tarik Body jika ada (Misal: POST/PUT)
        if (req.content_length > 0) {
            if (!recv_http_body(sock_client, &req, &buffer, &buf_limit, is_tls)) {
                http1_parser_free_memory(&req);
                break;
            }
        }

        // 4. Kirim Response (is_tls diteruskan di dalam req)
        http1_response_routing(sock_client, &req);

        keep_alive = req.is_keep_alive;
        http1_parser_free_memory(&req);
    }

    free(buffer);
    //fprintf(stderr, "[DEBUG] Sesi ditutup.\n");
    return keep_alive;
}

/**
 * handle_ssl_response_logic
 * Iki lho fungsine, Boss! Taruh di Manager.c biar satu rumah sama SSL.
 */

static void wait_for_ssl_write(int fd) {
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    poll(&pfd, 1, 100); // Tunggu 100ms sampai socket siap nulis
}

/**
 * handle_ssl_response_logic - FULL VERSION
 * Menangani File Statis & Auto-Index via SSL/TLS
 */
void http1_manager_ssl_response(int sock_client, RequestHeader *req) {
    //fprintf(stderr, "[SSL DEBUG] Memulai respons SSL untuk URI: %s\n", req->uri ? req->uri : "NULL");
    
    // 1. DAPATKAN KONTEKS VHOST (Gantikan get_active_root)
    VHostEntry *vh = http_vhost_get_context(req->host);
    const char *active_root = (vh) ? vh->root : config.document_root;

    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    // 1. VALIDASI AWAL & PENGECEKAN DIREKTORI
    if (!safe_path || stat(safe_path, &st) != 0) {
        goto send_404;
    }

    // --- LOGIKA AUTO-INDEX (Jika URI menunjuk ke Folder) ---
    if (S_ISDIR(st.st_mode)) {
        //fprintf(stderr, "[SSL DEBUG] URI adalah direktori, mencari index...\n");
        char index_path[4096];
        
        // A. Prioritas 1: index.html (Tetap di jalur SSL statis)
        snprintf(index_path, sizeof(index_path), "%s/index.html", safe_path);
        if (access(index_path, F_OK) == 0) {
            free(safe_path);
            safe_path = strdup(index_path);
            stat(safe_path, &st); // Perbarui stat untuk file index.html
            //fprintf(stderr, "[SSL DEBUG] Auto-index ditemukan: index.html\n");
        } 
        // B. Prioritas 2: index.php (Lempar balik ke routing agar diproses FastCGI)
        else {
            snprintf(index_path, sizeof(index_path), "%s/index.php", safe_path);
            if (access(index_path, F_OK) == 0) {
                //fprintf(stderr, "[SSL DEBUG] Auto-index ditemukan: index.php. Mengalihkan ke FastCGI...\n");
                strcat(req->uri, "index.php"); // Update URI di struct
                free(safe_path);
                http1_response_routing(sock_client, req); // RE-ROUTE!
                return; // KELUAR, karena akan ditangani oleh halmos_fcgi_request_stream
            } else {
                goto send_404; // Folder ada, tapi index kosong
            }
        }
    }

    // 2. CEK APAKAH FILE REGULER
    if (!S_ISREG(st.st_mode)) {
        //fprintf(stderr, "[SSL DEBUG] Bukan file reguler: %s\n", safe_path);
        goto send_404;
    }

    //fprintf(stderr, "[SSL DEBUG] Membuka file: %s (Size: %ld bytes)\n", safe_path, st.st_size);
    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        //fprintf(stderr, "[SSL DEBUG] Gagal open() file: %s (errno: %d)\n", safe_path, errno);
        if (safe_path) free(safe_path);
        return;
    }

    // 3. KIRIM HEADER VIA SSL
    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: Halmos-Savage/1.1\r\n"
        "Connection: %s\r\n\r\n",
        get_mime_type(req->uri), st.st_size, req->is_keep_alive ? "keep-alive" : "close");
    
    if (ssl_send(sock_client, header, h_len) <= 0) {
        close(fd);
        if (safe_path) free(safe_path);
        return;
    }

    // 4. KIRIM BODY DENGAN FLOW CONTROL (ANTI-MUTER)
    char *f_buf = malloc(32768);
    if (f_buf) {
        ssize_t n_read;
        while ((n_read = read(fd, f_buf, 32768)) > 0) {
            ssize_t total_sent = 0;
            while (total_sent < n_read) {
                ssize_t n_sent = ssl_send(sock_client, f_buf + total_sent, n_read - total_sent);
                
                if (n_sent > 0) {
                    total_sent += n_sent;
                } else {
                    // Handling Non-Blocking & SSL Buffer
                    SSL *ssl = ssl_get_for_fd(sock_client);
                    int err = SSL_get_error(ssl, (int)n_sent);
                    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                        wait_for_ssl_write(sock_client); // Fungsi poll()
                        continue; 
                    }
                    goto end_ssl_send; // Gagal total
                }
            }
        }
    }

end_ssl_send:
    if (f_buf) free(f_buf);
    close(fd);
    if (safe_path) free(safe_path);
    //fprintf(stderr, "[SSL DEBUG] Respons Selesai.\n---\n");
    return;

send_404:
    {
        //fprintf(stderr, "[SSL DEBUG] Mengirim 404 Not Found\n");
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\n404 Not Found";
        ssl_send(sock_client, nf, strlen(nf));
        if (safe_path) free(safe_path);
    }
}