#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/uio.h>

#include "halmos_fcgi.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_log.h"

#include <sys/time.h> // untuk timeval
#include <sys/sysinfo.h> // untuk info CPU dan RAM
#include <fcntl.h> // Untuk splice
#include <sys/resource.h> // Untuk rlimit (FD)


HalmosFCGI_Pool fcgi_pool;

static int halmos_fcgi_conn_acquire(const char *target, int port);
static void halmos_fcgi_conn_release(int sockfd);
static int add_fcgi_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len);
static int halmos_fcgi_splice_response(int fpm_fd, int sock_client, RequestHeader *req);
static void halmos_fcgi_send_stdin(int sockfd, int request_id, const void *data, int data_len);

/*
 * Metode yang digunakan adalah Pre-allocation streaming pool
 * Jadi diawal, sudah minta koneksi ke server (PHP-FPM, Spawn-fcgi, uwsgi) sebanyak 64 koneksi, 
 * dan sudah tidak minta-minta koneksi tambahan lagi
*/

void halmos_fcgi_pool_init(void) {
    // Panggil fungsi adaptive
    fcgi_pool.pool_size = g_fcgi_pool_size;

    // Alokasi memori secara dinamis
    fcgi_pool.connections = malloc(sizeof(HalmosFCGI_Conn) * fcgi_pool.pool_size);
    
    if (!fcgi_pool.connections) {
        write_log_error("[ERROR : halmos_fcgi.c] FATAL: Failed to allocate memory for %d pool connections!", fcgi_pool.pool_size);
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


/**
   Fungsi ini adalah fungsi utama di FCGI ini yang meneruskan request dari 
   HTTP ke backend (PHP, Python, Rust). Fungsi ini nanti dipanggil di
   halmos_http1_dynamic.c 
 */

int halmos_fcgi_request_stream(
    RequestHeader *req,
    int sock_client,
    const char *target,  // Tambahkan ini (bisa IP "127.0.0.1" atau path "/tmp/php.sock")
    int port,            // Tambahkan ini (9000 untuk TCP, atau 0 untuk Unix Socket)
    void *post_data,
    size_t post_data_len,
    size_t content_length
) {
    //printf("\n[FCGI_DEBUG] === New Request ===\n");
    //printf("[FCGI_DEBUG] Method: %s, URI: %s\n", req->method, req->uri);
    //printf("[FCGI_DEBUG] post_data_len: %zu, content_length: %zu\n", post_data_len, content_length);
    //HalmosFCGI_Response res = {NULL, NULL, 0};
    int fpm_sock = halmos_fcgi_conn_acquire(target, port);
    if (fpm_sock == -1) {
        return -1;
    }

    int request_id = 1;
    unsigned char gather_buf[16384]; // 16KB Write Buffer
    int g_ptr = 0;

    // 1. BEGIN REQUEST
    HalmosFCGI_Header *h = (HalmosFCGI_Header*)&gather_buf[g_ptr];
    memset(h, 0, sizeof(HalmosFCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id;
    h->contentLengthB0 = 8;
    g_ptr += sizeof(HalmosFCGI_Header);
    
    gather_buf[g_ptr++] = 0; // Role Responder B1
    gather_buf[g_ptr++] = FCGI_RESPONDER; // Role Responder B0
    gather_buf[g_ptr++] = FCGI_KEEP_CONN; // Keep Conn Flag
    memset(&gather_buf[g_ptr], 0, 5); // Reserved
    g_ptr += 5;

    // 2. PARAMS (Gathering)
    #define FCGI_ADD_PARAM(buf, key, val, offset) \
    do { \
        const char *v__ = (const char *)(val); \
        if (v__ && v__[0] != '\0') { \
            offset = add_fcgi_pair(buf, key, v__, offset, 16384); \
        } \
    } while (0)

    int params_start = g_ptr + sizeof(HalmosFCGI_Header);
    int p_offset = params_start;

    // Tambahkan params yang dibutuhkan backend Rust/PHP
    char full_script_path[1024];
    const char *active_root = get_active_root(req->host);

    // Logika: Jika root diakhiri '/' DAN uri diawali '/', buang salah satu
    if (active_root[strlen(active_root)-1] == '/' && req->uri[0] == '/') {
        snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, req->uri + 1);
    } else {
        snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, req->uri);
    }
    //printf("[FCGI_DEBUG] Script name (Fixed): %s\n", full_script_path);

    FCGI_ADD_PARAM(gather_buf, "SCRIPT_FILENAME", full_script_path, p_offset);
    FCGI_ADD_PARAM(gather_buf, "SCRIPT_NAME",     req->uri, p_offset); // WAJIB ADA
    FCGI_ADD_PARAM(gather_buf, "REQUEST_URI",     req->uri, p_offset); // WAJIB ADA
    FCGI_ADD_PARAM(gather_buf, "REQUEST_METHOD",  req->method, p_offset);
    FCGI_ADD_PARAM(gather_buf, "QUERY_STRING",    req->query_string ? req->query_string : "", p_offset);
    FCGI_ADD_PARAM(gather_buf, "HTTP_COOKIE",     req->cookie_data ? req->cookie_data : "", p_offset);

    // 1. Ambil IP Client
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    char remote_addr[INET_ADDRSTRLEN] = "127.0.0.1"; // Default
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_size) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, remote_addr, INET_ADDRSTRLEN);
    }
    FCGI_ADD_PARAM(gather_buf, "REMOTE_ADDR",     remote_addr, p_offset);
    
    // --- TAMBAHKAN INI UNTUK PYTHON/WSGI ---
    FCGI_ADD_PARAM(gather_buf, "SERVER_NAME",     config.server_name, p_offset);
    
    char s_port_str[10];
    snprintf(s_port_str, sizeof(s_port_str), "%d", config.server_port);
    FCGI_ADD_PARAM(gather_buf, "SERVER_PORT",     s_port_str, p_offset);
    
    FCGI_ADD_PARAM(gather_buf, "SERVER_PROTOCOL", "HTTP/1.1", p_offset);
    FCGI_ADD_PARAM(gather_buf, "GATEWAY_INTERFACE", "CGI/1.1", p_offset);
    
    char cl_str[20];
    if (content_length > 0) {
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM(gather_buf, "CONTENT_LENGTH", cl_str, p_offset);
        
        const char *ct = req->content_type;
        // Skip spasi atau tab di awal string (Trimming)
        if (ct) {
            while (*ct == ' ' || *ct == '\t') ct++;
        }

        // Gunakan default jika setelah di-trim stringnya kosong
        if (!ct || strlen(ct) == 0) {
            ct = "application/x-www-form-urlencoded";
        }

        // DEBUG DISINI
        //printf("[FCGI_DEBUG] Sending CONTENT_LENGTH: %s\n", cl_str);
        //printf("[FCGI_DEBUG] Sending CONTENT_TYPE: %s\n", ct);

        FCGI_ADD_PARAM(gather_buf, "CONTENT_TYPE", (ct && *ct) ? ct : "application/x-www-form-urlencoded", p_offset);
    } else {
        // Jika tidak ada body, baru kirim "0"
        FCGI_ADD_PARAM(gather_buf, "CONTENT_LENGTH", "0", p_offset);
    }

    int p_len = p_offset - params_start;
    #undef FCGI_ADD_PARAM

    // Header untuk Params
    HalmosFCGI_Header *ph = (HalmosFCGI_Header*)&gather_buf[g_ptr];
    ph->version = FCGI_VERSION_1;
    ph->type = FCGI_PARAMS;
    ph->requestIdB1 = (request_id >> 8) & 0xFF; // Tambahkan ini
    ph->requestIdB0 = request_id & 0xFF;
    ph->contentLengthB1 = (p_len >> 8) & 0xFF;
    ph->contentLengthB0 = p_len & 0xFF;
    ph->paddingLength = (8 - (p_len % 8)) % 8;
    g_ptr = p_offset;
    
    // Padding Params (biar pas 8 byte)
    for(int i=0; i<ph->paddingLength; i++) gather_buf[g_ptr++] = 0;

    // Header Params Kosong (End of Params)
    HalmosFCGI_Header *peh = (HalmosFCGI_Header*)&gather_buf[g_ptr];
    memset(peh, 0, sizeof(HalmosFCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF; // Tambahkan ini
    peh->requestIdB0 = request_id & 0xFF;
    g_ptr += sizeof(HalmosFCGI_Header);

    // KIRIM SEMUA HEADER SEKALIGUS (Write Gathering)
    send(fpm_sock, gather_buf, g_ptr, 0);

    // 3. STDIN & RESPONSE HANDLING
    if (content_length > 0) {
        // Kirim data yang sudah ada di buffer (post_data)
        if (post_data_len > 0) {
            //printf("[FCGI_DEBUG] Sending initial post_data (%zu bytes)...\n", post_data_len);
            halmos_fcgi_send_stdin(fpm_sock, request_id, post_data, (int)post_data_len);
        }
        
        // Jika masih ada sisa body di socket client (streaming)
        size_t total_sent = post_data_len;
        while (total_sent < content_length) {
            char buf[8192];
            //printf("[FCGI_DEBUG] Waiting for more data from client socket (sent: %zu/%zu)...\n", total_sent, content_length);
            ssize_t n = recv(sock_client, buf, sizeof(buf), 0);
            if (n <= 0) {
                //printf("[FCGI_DEBUG] Client closed connection or error (n=%zd)\n", n);
                break;
            }
            //printf("[FCGI_DEBUG] Received %zd bytes from client, forwarding to PHP...\n", n);
            // Bungkus sisa data ke dalam paket STDIN
            halmos_fcgi_send_stdin(fpm_sock, request_id, buf, (int)n);
            total_sent += n;
        }
        //printf("[FCGI_DEBUG] Total STDIN sent: %zu bytes\n", total_sent);
    }

    // KIRIM SINYAL AKHIR STDIN (WAJIB: Panjang 0)
    halmos_fcgi_send_stdin(fpm_sock, request_id, NULL, 0);
    //printf("[FCGI_DEBUG] Empty STDIN sent (End of Stream)\n");

    // 4. BACA RESPONSE
    int status = halmos_fcgi_splice_response(fpm_sock, sock_client, req);
    
    if (status != 0) {
        // Kirim 502 Bad Gateway jika gagal
    }
    
    // --- INI KUNCINYA ---
    // Jika koneksi bukan keep-alive, atau setelah response selesai diproses:
    if (req == NULL || !req->is_keep_alive) {
        shutdown(sock_client, SHUT_RDWR);
        close(sock_client);
    }

    //res = halmos_fcgi_read_response(fpm_sock);

    halmos_fcgi_conn_release(fpm_sock);
    return status;
}

/*
FUNGSI HELPER
*/

/*
Fungsi splice response ini bertugas mengirimkan data secara zero-copy.
Dari socket FCGI -> Buffer Kernel -> Socket Web server
Jadi fungsi ini cukup dipanggil dari halmos_fcgi_request_stream saja.
Tidak perlu dipanggil dari fungsi eksternal, seperti program pd biasanya
*/
int halmos_fcgi_splice_response(int fpm_fd, int sock_client, RequestHeader *req) {
    unsigned char h_buf[8];
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        write_log_error("[ERROR : halmos_fcgi.c] Pipe failed: %s", strerror(errno));
        return -1;
    }

    int header_sent = 0;
    char header_buffer[8192]; 
    int header_pos = 0;
    int success = 0;

    while (recv(fpm_fd, h_buf, 8, MSG_WAITALL) == 8) {
        HalmosFCGI_Header *h = (HalmosFCGI_Header *)h_buf;
        int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int plen = h->paddingLength;

        if (h->type == FCGI_STDOUT && clen > 0) {
            if (!header_sent) {
                // Ambil data ke buffer untuk cari \r\n\r\n
                int space = sizeof(header_buffer) - header_pos - 1;
                int to_read = (clen < space) ? clen : space;
                
                recv(fpm_fd, header_buffer + header_pos, to_read, MSG_WAITALL);
                header_pos += to_read;
                header_buffer[header_pos] = '\0';

                char *delim = strstr(header_buffer, "\r\n\r\n");
                if (delim) {
                    // --- DETEKSI STATUS (WAJIB ADA BIAR REDIRECT JALAN) ---
                    int status_code = 200;
                    char *s_ptr = strcasestr(header_buffer, "Status:");
                    if (s_ptr) {
                        status_code = atoi(s_ptr + 8);
                    } else if (strcasestr(header_buffer, "Location:")) {
                        status_code = 302; // Browser butuh ini untuk pindah halaman
                    }
                    // --- DETEKSI STATUS ---
                    const char *status_msg = get_status_text(status_code);

                    // 1. Kirim Status Line Halmos
                    char response_start[512];
                    int start_len = snprintf(response_start, sizeof(response_start),
                        "HTTP/1.1 %d %s\r\n"
                        "Server: Halmos-Core/2.1\r\n"
                        "X-Content-Type-Options: nosniff\r\n" // <--- TAMBAHKAN INI
                        "Connection: %s\r\n",
                        status_code, status_msg, (req && req->is_keep_alive) ? "keep-alive" : "close");
                    
                    // Gunakan MSG_MORE agar kernel menunggu header berikutnya sebelum dikirim
                    send(sock_client, response_start, start_len, MSG_MORE | MSG_NOSIGNAL);

                    // 2. Kirim Header murni dari PHP (sampai \r\n\r\n)
                    int header_only_len = (delim - header_buffer) + 4; 
                    send(sock_client, header_buffer, header_only_len, MSG_NOSIGNAL);
                    
                    header_sent = 1;

                    // 3. Kirim sisa BODY yang tidak sengaja terbaca ke buffer
                    int body_in_buffer = header_pos - header_only_len;
                    if (body_in_buffer > 0) {
                        send(sock_client, header_buffer + header_only_len, body_in_buffer, MSG_NOSIGNAL);
                    }

                    // 4. Splice sisa data (Jalur Tol)
                    int remain_in_chunk = clen - to_read; 
                    if (remain_in_chunk > 0) {
                        splice(fpm_fd, NULL, pipe_fds[1], NULL, remain_in_chunk, SPLICE_F_MOVE | SPLICE_F_MORE);
                        splice(pipe_fds[0], NULL, sock_client, NULL, remain_in_chunk, SPLICE_F_MOVE | SPLICE_F_MORE);
                    }
                }
                else if (header_pos >= (int)sizeof(header_buffer) - 1) {
                    // Emergency: Header kepanjangan sampai 8KB dan belum ketemu \r\n\r\n
                    // Di sini harusnya kirim 502 atau paksa kirim apa adanya
                    write_log_error("[ERROR] Header too large, delimiter not found");
                }
            } else {
                // Jalur Tol Zero Copy untuk paket selanjutnya
                splice(fpm_fd, NULL, pipe_fds[1], NULL, clen, SPLICE_F_MOVE | SPLICE_F_MORE);
                splice(pipe_fds[0], NULL, sock_client, NULL, clen, SPLICE_F_MOVE | SPLICE_F_MORE);
            }
        }
        else if (h->type == FCGI_STDERR && clen > 0) {
            char *err = malloc(clen + 1);
            recv(fpm_fd, err, clen, MSG_WAITALL);
            err[clen] = '\0';
            write_log_error("[ERROR : halmos_fcgi.c] BACKEND_STDERR %s", err);
            free(err);
        }
        else if (h->type == FCGI_END_REQUEST) {
            /*
            Menghapus Junk :Istilahnya Protocol Desynchronization.
            Tanpa pembersihan junk yang sempurna, kita seperti naruh piring kotor 
            ke rak piring bersih (Pool). 
            Pas orang berikutnya mau pakai piring itu, 
            dia dapet sisa makanan (data sampah) yang bikin semuanya kacau.
            Ini yang menyebabkan PHP-FPM mati kalau junk ini tidak dibersihkan!
            */
            success = 1;
            int total_junk = clen + plen;
            
            // Perbaikan: Deklarasikan junk_buf di sini
            char junk_buf[256]; 
            while (total_junk > 0) {
                int to_read = (total_junk > 256) ? 256 : total_junk;
                // Pastikan variabelnya sinkron: junk_buf
                recv(fpm_fd, junk_buf, to_read, MSG_WAITALL);
                total_junk -= to_read;
            }
            break;
        }

        if (plen > 0) {
            unsigned char dummy_padding[256];
            recv(fpm_fd, dummy_padding, plen, MSG_WAITALL);
        }
    }

    // CEK LOG AKHIR: Kenapa keluar dari loop?
    if (!success) {
        //fprintf(stderr, "[DEBUG] Loop finished without FCGI_END_REQUEST. success=%d, header_sent=%d\n", success, header_sent);
        write_log_error("[ERROR : halmos_fcgi.c] Loop finished without FCGI_END_REQUEST. success=%d, header_sent=%d", success, header_sent);
    }

    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return success ? 0 : -1;
}

void halmos_fcgi_send_stdin(int sockfd, int request_id, const void *data, int data_len) {
    int sent_so_far = 0;
    
    if (data_len > 0 && data != NULL) {
        while (sent_so_far < data_len) {
            int chunk_size = (data_len - sent_so_far > 65535) ? 65535 : (data_len - sent_so_far);
            int padding_len = (8 - (chunk_size % 8)) % 8;
            unsigned char padding[8] = {0};

            HalmosFCGI_Header header; // Pakai struct lo sendiri
            memset(&header, 0, sizeof(header));
            header.version = FCGI_VERSION_1;
            header.type = FCGI_STDIN;
            header.requestIdB1 = (request_id >> 8) & 0xFF;
            header.requestIdB0 = request_id & 0xFF;
            header.contentLengthB1 = (chunk_size >> 8) & 0xFF;
            header.contentLengthB0 = chunk_size & 0xFF;
            header.paddingLength = padding_len;

            // Kumpulkan 3 bagian data dalam satu iovec
            struct iovec iov[3];
            iov[0].iov_base = &header;
            iov[0].iov_len  = 8;
            iov[1].iov_base = (char*)data + sent_so_far;
            iov[1].iov_len  = chunk_size;
            iov[2].iov_base = padding;
            iov[2].iov_len  = padding_len;

            // Kirim sekaligus (Atomic)
            if (writev(sockfd, iov, 3) < 0) {
                write_log_error("[ERROR] Failed to send STDIN: %s", strerror(errno));
                break;
            }
            
            sent_so_far += chunk_size;
        }
    } else {
        // Kirim paket penutup (Empty STDIN)
        HalmosFCGI_Header empty_h = {0};
        empty_h.version = FCGI_VERSION_1;
        empty_h.type = FCGI_STDIN;
        empty_h.requestIdB0 = request_id; // Simple ID handle
        
        send(sockfd, &empty_h, 8, MSG_NOSIGNAL);
    }
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
        if (!stored && can_store_in_pool) {
            // Ini kondisi langka: kuota masih ada tapi slot pool penuh total
            write_log_error("[DEBUG] Pool full, connection will be temporary (non-pooled)");
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

// Helper internal untuk menambahkan pasangan Params
int add_fcgi_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    int name_len = (int)strlen(name);
    const char* val_ptr = value ? value : "";
    int value_len = (int)strlen(val_ptr);

    if (offset + name_len + value_len + 8 > max_len) return 0;

    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else dest[offset++] = (unsigned char)name_len;

    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else dest[offset++] = (unsigned char)value_len;

    memcpy(dest + offset, name, name_len);
    offset += name_len;
    memcpy(dest + offset, val_ptr, value_len);
    return offset + value_len;
}

