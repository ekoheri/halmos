#include "halmos_fcgi_proto.h"
#include "halmos_fcgi_pool.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef GATHER_BUF_SIZE
#define GATHER_BUF_SIZE 65536
#endif

// Helper internal untuk pasangan key-value
static int safe_send_all(int sockfd, const void *buf, size_t len);

static int  fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len);

static ssize_t fcgi_smart_response(int fd, const void *buf, size_t len, bool is_tls);

//static int fcgi_io_splice_response(int fpm_fd, int sock_client, RequestHeader *req);

/* --- CORE FUNCTIONS --- */

int fcgi_proto_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id) {
    int fpm_sock = fcgi_pool_conn_acquire(target, port);
    if (fpm_sock == -1) return -1;

    HalmosFCGI_Header *h = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(h, 0, sizeof(HalmosFCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id & 0xFF;
    h->requestIdB1 = (request_id >> 8) & 0xFF;
    h->contentLengthB0 = 8;
    *g_ptr += sizeof(HalmosFCGI_Header);
    
    gather_buf[(*g_ptr)++] = 0; // Role Responder B1
    gather_buf[(*g_ptr)++] = FCGI_RESPONDER; // Role Responder B0
    gather_buf[(*g_ptr)++] = FCGI_KEEP_CONN; // Keep Conn Flag
    memset(&gather_buf[*g_ptr], 0, 5); 
    *g_ptr += 5;

    return fpm_sock;
}

void fcgi_proto_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id) {
    (void)sock_client;
    
    // 1. Simpan posisi header PARAMS
    int header_pos = *g_ptr;
    *g_ptr += sizeof(HalmosFCGI_Header); // Loncat dulu agar p_offset mulai setelah header
    int p_offset = *g_ptr;

    VHostEntry *vh = http_vhost_get_context(req->host);
    const char *active_root = (vh) ? vh->root : config.document_root;
    char full_script_path[4096];
    char script_name_only[512] = {0};

    // Script & Path Logic
    const char *raw_uri = req->uri ? req->uri : "/";

    // Salin ke buffer script_name_only
    snprintf(script_name_only, sizeof(script_name_only), "%s", raw_uri);

    // 1. Buang Query String ('?') jika ada
    char *qmark = strchr(script_name_only, '?');
    if (qmark) {
        *qmark = '\0';
    }

    // 2. Buang PATH_INFO jika ada (misal /test.php/extra/path -> /test.php)
    // Jika req->path_info ada, kita potong string script_name_only di awal munculnya path_info
    if (req->path_info && strlen(req->path_info) > 0) {
        char *pinfo_pos = strstr(script_name_only, req->path_info);
        if (pinfo_pos && pinfo_pos > script_name_only) {
            *pinfo_pos = '\0';
        }
    }

    // Rakit FULL SCRIPT FILENAME untuk PHP-FPM
    snprintf(full_script_path, sizeof(full_script_path), "%s%s", active_root, 
            (active_root[strlen(active_root)-1] == '/' && script_name_only[0] == '/') ? script_name_only + 1 : script_name_only);

    // Macro yang sedikit lebih galak (kasih log kalau NULL)
    #define FCGI_ADD_PARAM_SAFE(key, val) do { \
        const char *v__ = (const char *)(val); \
        if (v__) { \
            p_offset = fcgi_proto_add_pair(gather_buf, key, v__, p_offset, GATHER_BUF_SIZE); \
        } \
    } while (0)

    // --- MANDATORY CGI PARAMS ---
    FCGI_ADD_PARAM_SAFE("DOCUMENT_ROOT",   active_root);
    FCGI_ADD_PARAM_SAFE("SCRIPT_FILENAME", full_script_path);
    FCGI_ADD_PARAM_SAFE("SCRIPT_NAME",     script_name_only);
    FCGI_ADD_PARAM_SAFE("PHP_SELF",        script_name_only);
    FCGI_ADD_PARAM_SAFE("REQUEST_URI",     req->uri);
    FCGI_ADD_PARAM_SAFE("REQUEST_METHOD",  req->method);
    FCGI_ADD_PARAM_SAFE("QUERY_STRING",    req->query_string ? req->query_string : "");
    FCGI_ADD_PARAM_SAFE("PATH_INFO",       req->path_info ? req->path_info : "");
    FCGI_ADD_PARAM_SAFE("SERVER_PROTOCOL", "HTTP/1.1");
    FCGI_ADD_PARAM_SAFE("GATEWAY_INTERFACE", "CGI/1.1");
    
    // --- REMOTE ADDR (KRUSIAL: Kasih fallback!) ---
    FCGI_ADD_PARAM_SAFE("REMOTE_ADDR",     req->client_ip ? req->client_ip : "127.0.0.1");
    FCGI_ADD_PARAM_SAFE("SERVER_NAME",     req->host ? req->host : config.server_name);
    
    // --- TLS DETECTION ---
    if (req->is_tls) {
        FCGI_ADD_PARAM_SAFE("HTTPS", "on");
        FCGI_ADD_PARAM_SAFE("REQUEST_SCHEME", "https");
    } else {
        FCGI_ADD_PARAM_SAFE("REQUEST_SCHEME", "http");
    }

    char s_port_str[10];
    snprintf(s_port_str, sizeof(s_port_str), "%d", config.server_port);
    FCGI_ADD_PARAM_SAFE("SERVER_PORT", s_port_str);
    
    if (req->cookie_data) FCGI_ADD_PARAM_SAFE("HTTP_COOKIE", req->cookie_data);

    // --- CONTENT HANDLING (PENYEBAB $_FILES KOSONG) ---
    if (content_length > 0) {
        char cl_str[24];
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        FCGI_ADD_PARAM_SAFE("CONTENT_LENGTH", cl_str);
        
        const char *type_to_send = req->content_type;

        if (type_to_send) {
            //fprintf(stderr, "[H2-FCGI-DEBUG] CONTENT_TYPE DETECTED: %s\n", type_to_send);
        } else {
            //fprintf(stderr, "[H2-FCGI-DEBUG] CONTENT_TYPE MISSING! Falling back to urlencoded.\n");
            type_to_send = "application/x-www-form-urlencoded";
        }
        
        // Kirim yang sebenarnya dipilih
        FCGI_ADD_PARAM_SAFE("CONTENT_TYPE", type_to_send);
    }

    // 2. Finalisasi Header PARAMS
    int p_len = p_offset - *g_ptr;
    int pad = (8 - (p_len % 8)) % 8;

    HalmosFCGI_Header *ph = (HalmosFCGI_Header*)&gather_buf[header_pos];
    ph->version = FCGI_VERSION_1;
    ph->type = FCGI_PARAMS;
    ph->requestIdB1 = (request_id >> 8) & 0xFF;
    ph->requestIdB0 = request_id & 0xFF;
    ph->contentLengthB1 = (p_len >> 8) & 0xFF;
    ph->contentLengthB0 = p_len & 0xFF;
    ph->paddingLength = (unsigned char)pad;
    ph->reserved = 0;

    // Update global pointer ke posisi setelah data + padding
    *g_ptr = p_offset;
    for(int i = 0; i < pad; i++) gather_buf[(*g_ptr)++] = 0;

    // 3. Tambahkan EMPTY PARAMS (Tanda akhir params)
    HalmosFCGI_Header *peh = (HalmosFCGI_Header*)&gather_buf[*g_ptr];
    memset(peh, 0, sizeof(HalmosFCGI_Header));
    peh->version = FCGI_VERSION_1;
    peh->type = FCGI_PARAMS;
    peh->requestIdB1 = (request_id >> 8) & 0xFF;
    peh->requestIdB0 = request_id & 0xFF;
    *g_ptr += sizeof(HalmosFCGI_Header);
}

void fcgi_proto_send_stdin(int sockfd, int request_id, const void *data, int data_len) {
    //fprintf(stderr, "[TRACE-STDIN] Masuk ke fcgi_proto_send_stdin\n");
    //fprintf(stderr, "[TRACE-STDIN] ReqID: %d | DataAddr: %p | Len: %d\n", request_id, data, data_len);

    if (data_len > 0 && data != NULL) {
        int sent_payload = 0;
        while (sent_payload < data_len) {
            int chunk = (data_len - sent_payload > 32768) ? 32768 : (data_len - sent_payload);
            int pad = (8 - (chunk % 8)) % 8;
            
            unsigned char record_buf[sizeof(HalmosFCGI_Header) + 32768 + 8]; 
            int r_ptr = 0;

            HalmosFCGI_Header *h = (HalmosFCGI_Header*)record_buf;
            h->version = FCGI_VERSION_1;
            h->type = FCGI_STDIN;
            h->requestIdB1 = (request_id >> 8) & 0xFF;
            h->requestIdB0 = request_id & 0xFF;
            h->contentLengthB1 = (chunk >> 8) & 0xFF;
            h->contentLengthB0 = chunk & 0xFF;
            h->paddingLength = (unsigned char)pad;
            h->reserved = 0;
            r_ptr += sizeof(HalmosFCGI_Header);

            memcpy(record_buf + r_ptr, (char*)data + sent_payload, chunk);
            r_ptr += chunk;
            
            if (pad > 0) {
                memset(record_buf + r_ptr, 0, pad);
                r_ptr += pad;
            }

            if (safe_send_all(sockfd, record_buf, r_ptr) < 0) {
                //fprintf(stderr, "[TRACE-STDIN] Error saat kirim chunk!\n");
                return;
            }
            sent_payload += chunk;
        }
        //fprintf(stderr, "[TRACE-STDIN] Berhasil kirim total payload: %d\n", sent_payload);
    }

    // Kirim Empty STDIN (EOF) - HANYA JIKA data_len >= 0
    HalmosFCGI_Header empty_h = {0};
    empty_h.version = FCGI_VERSION_1;
    empty_h.type = FCGI_STDIN;
    empty_h.requestIdB1 = (request_id >> 8) & 0xFF;
    empty_h.requestIdB0 = request_id & 0xFF;
    
    if (safe_send_all(sockfd, &empty_h, sizeof(empty_h)) >= 0) {
        //fprintf(stderr, "[TRACE-STDIN] EOF (Empty STDIN) Sent for ReqID: %d\n", request_id);
    }
}

/**
 * fcgi_splice_response: Otak dari streaming response Backend khusus untuk HTTP1.
 * fcgi_io_splice_response: Versi Ultimate (Anti-Hang & Anti-Poison)
 * Fix: Menambahkan timeout read agar worker tidak hang selamanya jika backend stuck.
 * Fix: Memastikan record dibaca sampai END_REQUEST untuk mencegah pool corruption.
 */
int fcgi_io_splice_response(int fpm_fd, int sock_client, RequestHeader *req) {
    unsigned char h_buf[8];
    int pipe_fds[2];
    bool is_tls = req->is_tls;
    bool use_splice = !is_tls;
    
    char body_temp[16384];
    char header_buffer[8192]; 
    int header_pos = 0;
    bool header_sent = false;
    bool is_redirect = false;
    int final_status = -1; // Default gagal (Poisoned state)

    // 1. SET TIMEOUT: Mencegah Worker Thread Hang Selamanya
    struct timeval tv;
    tv.tv_sec = 30; // Timeout 30 detik (Standar upstream)
    tv.tv_usec = 0;
    if (setsockopt(fpm_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        write_log_error("[FCGI] Warning: Could not set SO_RCVTIMEO: %s", strerror(errno));
    }

    if (use_splice && pipe(pipe_fds) < 0) {
        use_splice = false;
    }

    /* --- LOOP UTAMA: FASTCGI RECORD PARSING --- */
    while (1) {
        // Baca Header (MSG_WAITALL akan patuh pada SO_RCVTIMEO)
        ssize_t n_head = recv(fpm_fd, h_buf, 8, MSG_WAITALL);
        if (n_head != 8) {
            if (n_head < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                write_log_error("[FCGI] Timeout: Backend unresponsive for 30s at URI: %s", req->uri);
            } else {
                write_log_error("[FCGI] Connection lost/Header malformed.");
            }
            break; 
        }

        HalmosFCGI_Header *h = (HalmosFCGI_Header *)h_buf;
        int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int plen = h->paddingLength;

        if (h->type == FCGI_STDOUT) {
            if (clen > 0) {
                if (!header_sent) {
                    /* --- FASE 1: PARSING HEADER HTTP --- */
                    int space = sizeof(header_buffer) - header_pos - 1;
                    int to_read = (clen < space) ? clen : space;
                    
                    if (recv(fpm_fd, header_buffer + header_pos, to_read, MSG_WAITALL) != to_read) break;
                    header_pos += to_read;
                    header_buffer[header_pos] = '\0';

                    char *delim = strstr(header_buffer, "\r\n\r\n");
                    if (delim) {
                        int status_code = 200;
                        char *s_ptr = strcasestr(header_buffer, "Status:");
                        if (s_ptr) status_code = atoi(s_ptr + 8);
                        else if (strcasestr(header_buffer, "Location:")) status_code = 302;
                        is_redirect = (status_code >= 300 && status_code < 400);

                        // Cek apakah PHP sudah mengirimkan Content-Length
                        bool has_content_length = (strcasestr(header_buffer, "Content-Length:") != NULL);

                        // Susun Respon HTTP/1.1 ke Klien
                        char res_start[1024];
                        int s_len;

                        if (is_redirect) {
                            // Untuk redirect (302), paksa Content-Length: 0 di header utama jika belum ada
                            s_len = snprintf(res_start, sizeof(res_start),
                                "HTTP/1.1 %d %s\r\nServer: Halmos\r\n%s%sConnection: %s\r\n",
                                status_code, get_status_text(status_code),
                                has_content_length ? "" : "Content-Length: 0\r\n",
                                "", // Tempat tambahan jika diperlukan
                                req->is_keep_alive ? "keep-alive" : "close");
                        } else {
                            s_len = snprintf(res_start, sizeof(res_start),
                                "HTTP/1.1 %d %s\r\nServer: Halmos\r\nTransfer-Encoding: chunked\r\nConnection: %s\r\n",
                                status_code, get_status_text(status_code),
                                req->is_keep_alive ? "keep-alive" : "close");
                        }
                        
                        if (fcgi_smart_response(sock_client, res_start, s_len, is_tls) < 0) break;
                        
                        // Kirim header asli dari PHP-FPM (termasuk \r\n\r\n penutupnya)
                        int h_only_len = (delim - header_buffer) + 4; 
                        if (fcgi_smart_response(sock_client, header_buffer, h_only_len, is_tls) < 0) break;
                        
                        header_sent = true;

                        // Jika redirect, kita tidak perlu memproses body sama sekali
                        if (is_redirect) {
                            // Kuras sisa buffer record FPM jika ada lalu keluar
                            int remain = clen - (header_pos);
                            while (remain > 0) {
                                int pull = (remain > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : remain;
                                if (recv(fpm_fd, body_temp, pull, MSG_WAITALL) != pull) break;
                                remain -= pull;
                            }
                            final_status = 0;
                            break; 
                        }

                        // Handle sisa body normal (selain redirect)
                        int body_in_buf = header_pos - h_only_len;
                        if (body_in_buf > 0) {
                            char sz[16];
                            int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", body_in_buf);
                            fcgi_smart_response(sock_client, sz, sz_l, is_tls);
                            fcgi_smart_response(sock_client, header_buffer + h_only_len, body_in_buf, is_tls);
                            fcgi_smart_response(sock_client, "\r\n", 2, is_tls);
                        }

                        int remain = clen - to_read;
                        while (remain > 0) {
                            int pull = (remain > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : remain;
                            if (recv(fpm_fd, body_temp, pull, MSG_WAITALL) != pull) goto cleanup_error;
                            
                            char sz[16];
                            int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", pull);
                            fcgi_smart_response(sock_client, sz, sz_l, is_tls);
                            fcgi_smart_response(sock_client, body_temp, pull, is_tls);
                            fcgi_smart_response(sock_client, "\r\n", 2, is_tls);
                            remain -= pull;
                        }
                    }
                } else {
                    /* --- FASE 2: STREAMING BODY (CHUNKED) --- */
                    if (!is_redirect) {
                        char sz[16];
                        int sz_l = snprintf(sz, sizeof(sz), "%X\r\n", clen);
                        if (fcgi_smart_response(sock_client, sz, sz_l, is_tls) < 0) break;
                    }

                    if (use_splice) {
                        int to_move = clen;
                        while (to_move > 0) {
                            // 1. Pindahkan dari Backend ke Pipe (In)
                            ssize_t n_in = splice(fpm_fd, NULL, pipe_fds[1], NULL, to_move, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                            
                            if (n_in < 0) {
                                if (errno == EAGAIN || errno == EINTR) continue;
                                goto cleanup_error;
                            } else if (n_in == 0) goto cleanup_error; // Backend closed

                            // 2. Pindahkan dari Pipe ke Client (Out)
                            // Kita harus menguras apa yang baru saja masuk ke pipe
                            int pipe_level = (int)n_in;
                            while (pipe_level > 0) {
                                ssize_t n_out = splice(pipe_fds[0], NULL, sock_client, NULL, pipe_level, SPLICE_F_MOVE);
                                if (n_out <= 0) {
                                    if (n_out < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                                    goto cleanup_error; // Client closed/error
                                }
                                pipe_level -= (int)n_out;
                            }
                            
                            to_move -= (int)n_in;
                        }
                    } else {
                        int to_pull = clen;
                        while (to_pull > 0) {
                            int pull = (to_pull > (int)sizeof(body_temp)) ? (int)sizeof(body_temp) : to_pull;
                            if (recv(fpm_fd, body_temp, pull, MSG_WAITALL) != pull) goto cleanup_error;
                            if (!is_redirect) {
                                if (fcgi_smart_response(sock_client, body_temp, pull, is_tls) < 0) goto cleanup_error;
                            }
                            to_pull -= pull;
                        }
                    }
                    if (!is_redirect) fcgi_smart_response(sock_client, "\r\n", 2, is_tls);
                }
            }
        } 
        else if (h->type == FCGI_STDERR && clen > 0) {
            char *err_msg = malloc(clen + 1);
            if (err_msg) {
                //recv(fpm_fd, err_msg, clen, MSG_WAITALL);
                if (recv(fpm_fd, err_msg, clen, MSG_WAITALL) != clen)
                    goto cleanup_error;
                err_msg[clen] = '\0';
                write_log_error("[PHP-STDERR] %s", err_msg);
                free(err_msg);
            }
        }
        else if (h->type == FCGI_END_REQUEST) {
            unsigned char end_payload[8]; 
            if (recv(fpm_fd, end_payload, 8, MSG_WAITALL) == 8) {
                if (!is_redirect && header_sent) {
                    fcgi_smart_response(sock_client, "0\r\n\r\n", 5, is_tls);
                }
                final_status = 0; // KONDISI SUKSES MUTLAK
            }
            break; 
        }

        // Kuras Padding
        if (plen > 0) {
            char junk[256];
            if (recv(fpm_fd, junk, plen, MSG_WAITALL) != plen) break;
        }
    }

cleanup_error:
    if (use_splice) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }

    if (final_status != 0) {
        /* STATE INCONSISTENT: Socket beracun, buang dari pool! */
        write_log_error("[FCGI] Protocol Desync or Timeout. Closing backend socket.");
        close(fpm_fd); 
        return -2; 
    }

    return 0;
}


/* --- INTERNAL HELPER --- */

int safe_send_all(int sockfd, const void *buf, size_t len) {
    size_t total_sent = 0;
    const unsigned char *ptr = (const unsigned char *)buf;

    while (total_sent < len) {
        ssize_t n = send(sockfd, ptr + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (errno == EINTR) continue; // Terganggu sinyal, coba lagi
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Di sini biasanya kita pakai poll/select, 
                // tapi untuk FCGI kita asumsikan blocking mode yang aman.
                continue; 
            }
            return -1; // Error beneran (koneksi putus/SIGPIPE)
        }
        total_sent += n;
    }
    return 0;
}

/**
 * Menambahkan pasangan Key-Value ke buffer FastCGI sesuai spesifikasi.
 * Mendukung format 1-byte length (< 128) dan 4-byte length (>= 128).
 */
int fcgi_proto_add_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len) {
    if (!name) return offset;

    size_t name_len = strlen(name);
    const char* val_ptr = value ? value : "";
    size_t value_len = strlen(val_ptr);

    // 1. Hitung berapa byte yang dibutuhkan untuk menyimpan informasi panjang (length)
    // Spesifikasi FastCGI: Jika length > 127, gunakan 4 byte (bit paling kiri diset 1)
    int h_name = (name_len > 127) ? 4 : 1;
    int h_val  = (value_len > 127) ? 4 : 1;
    
    // 2. Cek apakah buffer cukup sebelum menulis
    if (offset + h_name + h_val + (int)name_len + (int)value_len > max_len) {
        //fprintf(stderr, "[FCGI-ERR] Buffer overflow saat menambah param: %s\n", name);
        return offset; 
    }

    // 3. Tulis Panjang Nama (Name Length)
    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)name_len;
    }

    // 4. Tulis Panjang Nilai (Value Length)
    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)value_len;
    }

    // 5. Tulis Data Nama
    memcpy(dest + offset, name, name_len);
    offset += name_len;

    // 6. Tulis Data Nilai
    memcpy(dest + offset, val_ptr, value_len);
    offset += value_len;
    
    return offset;
}

/**
 * fcgi_smart_response: Wrapper internal untuk memastikan data terkirim
 * baik lewat SSL atau socket biasa.
 */

ssize_t fcgi_smart_response(int fd, const void *buf, size_t len, bool is_tls) {
    if (is_tls) {
        // Panggil fungsi pusat yang sudah pinter handle WANT_WRITE (code 3)
        // Kita loop di sini biar semua chunk datanya beneran keluar
        size_t total_sent = 0;
        while (total_sent < len) {
            ssize_t n = ssl_send(fd, (const char*)buf + total_sent, len - total_sent);
            if (n > 0) {
                total_sent += n;
            } else if (n == 0) {
                // Pakai wait_for_write yang kita buat di manager tadi
                // Kalau fungsi wait_for_write juga static, terpaksa bikin poll lokal di sini
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                poll(&pfd, 1, 10); 
            } else {
                return -1; // Fatal error
            }
        }
        return total_sent;
    }
    // Jalur Plaintext (Non-TLS)
    return send(fd, buf, len, MSG_NOSIGNAL);
}


