#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_global.h"
#include "halmos_config.h" 
#include "halmos_http1_manager.h"
#include "halmos_http_bridge.h"
#include "halmos_event_loop.h"
#include "halmos_log.h"
#include "halmos_tls.h"
#include "halmos_websocket.h"

#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

// Fungsi pembantu khusus debug HTTP/HTTPS
// Fungsi ini saya remark, karena memang tidak dipakai. 
// Hanya untuk iseng aja, mengintip model data HTTP/HTTPS
// ======================== DEBUG TOOL START ========================
/*
static void hex_dump_debug(int fd, const char *data, ssize_t size) {
    if (!data || size <= 0) return; 

    // Samakan semua ke size_t biar compiler gak rewel
    size_t s_size = (size_t)size;
    size_t limit = (s_size > 256) ? 256 : s_size;

    printf("\n[DATA-CHIPERTEXT] FD: %d (%zu bytes)\n", fd, s_size);
    printf("Offset    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  |  ASCII\n");
    printf("-------------------------------------------------------------------\n");
    
    // Pakai size_t di sini
    for (size_t i = 0; i < limit; i += 16) {
        printf("%08X  ", (unsigned int)i);
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < limit) {
                printf("%02X ", (unsigned char)data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" |  ");
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < limit) {
                unsigned char c = (unsigned char)data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("\n");
    }
    printf("-------------------------------------------------------------------\n");
    fflush(stdout); // Biar langsung nongol di terminal
}
// ======================== DEBUG TOOL END ==========================
*/

static halmos_protocol_t bridge_detect(int fd, SSL *ssl);

/**
 * Multiplexer Utama: Jembatan antara Core FD dan Protocol Manager
 */
int bridge_dispatch(int sock_client) {
    // --- [ LANGKAH 0: CEK STATUS WEBSOCKET ] ---
    // Jika FD ini sudah terdaftar sebagai WebSocket, langsung lempar ke dispatcher WS.
    // Kita nggak perlu peek-peek lagi, langsung gas pol.

    //fprintf(stderr, "[DEBUG-BRIDGE] Thread %ld menangani FD %d\n", (long)pthread_self(), sock_client);
    if (halmos_is_websocket_fd(sock_client)) {
        return halmos_ws_dispatch(sock_client);
    }

    char peek_buf[1];     // cukup diset 1 untuk kebutuhan jalannya sistem normal
    //char peek_buf[256]; // di set 256 untuk kebutuhan debug data

    // 1. Ambil state SSL jika ada
    SSL *ssl = get_ssl_for_fd(sock_client);
    bool is_actually_tls = (ssl != NULL);

    // 2. DETEKSI AWAL: Intip byte pertama kalau belum yakin ini TLS
    if (!is_actually_tls) {
        ssize_t n = recv(sock_client, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
        
        // CCTV 1
        //fprintf(stderr, "[DEBUG-BRIDGE] FD %d: recv peek result = %zd\n", sock_client, n);
        //di set 256 untuk kebutuhan debug data
        //ssize_t n = recv(sock_client, peek_buf, 256, MSG_PEEK | MSG_DONTWAIT);
        
        if (n < 0) {
            // CCTV 2
            //fprintf(stderr, "[DEBUG-BRIDGE] FD %d: recv error, errno = %d (%s)\n", 
            //    sock_client, errno, strerror(errno));

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                rearm_epoll_oneshot(sock_client);
                return 1; 
            }
            return 0; 
        }

        // CCTV 3
        if (n == 0) {
            //fprintf(stderr, "[DEBUG-BRIDGE] FD %d: recv returned 0 (Client closed prematurely)\n", sock_client);
            return 0; 
        }

        // CCTV 4
        //fprintf(stderr, "[DEBUG-BRIDGE] FD %d: Byte pertama terdeteksi: 0x%02X\n", 
        //    sock_client, (unsigned char)peek_buf[0]);
        // ======================== DEBUG START ========================
        // Memanggil helper hex dump untuk ngintip data HTTP/HTTPS
        // hex_dump_debug(sock_client, peek_buf, n);
        // ======================== DEBUG END ==========================

        if (peek_buf[0] == 0x16) {
            is_actually_tls = true;
            
            // Lazy Allocation: Baru bikin objek SSL di sini!
            if (config.tls_enabled) {
                ssl = SSL_new(halmos_tls_ctx);
                SSL_set_fd(ssl, sock_client);
                set_ssl_for_fd(sock_client, ssl);
            }
        }
    }

    // 3. EKSEKUSI JALUR TLS
    if (is_actually_tls) {
        if (!config.tls_enabled) {
            write_log_error("[BRIDGE] Reject: TLS request on HTTP-only server. FD %d", sock_client);
            char *msg = "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: text/plain\r\n"
                            "Connection: close\r\n\r\n"
                            "This server only speaks HTTP, Boss!";
            
            send(sock_client, msg, strlen(msg), MSG_NOSIGNAL);

            return 0; 
        }

        if (!ssl) return 0;

        // Pastikan Handshake Selesai
        if (!SSL_is_init_finished(ssl)) {
            int r = SSL_accept(ssl);
            if (r <= 0) {
                int err = SSL_get_error(ssl, r);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    rearm_epoll_oneshot(sock_client);
                    return 1;
                }
                return 0; // Handshake gagal
            }
        }
    } 
    // 4. EKSEKUSI JALUR PLAIN (Kalau TLS aktif tapi user maksa HTTP)
    else if (config.tls_enabled) {
        char *msg = "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n\r\n"
                                "<html><head><title>400 Bad Request</title></head>"
                                "<body style='font-family:sans-serif; text-align:center; padding-top:50px;'>"
                                "<h1>HTTPS Required</h1>"
                                "<p>Halmos Server only accepts <b>HTTPS</b> connections, Boss!</p>"
                                "<hr><i style='color:gray;'>Halmos Core Engine</i>"
                                "</body></html>";
        send(sock_client, msg, strlen(msg), MSG_NOSIGNAL);
        return 0; 
    }

    // 5. PENYERAHAN KE PROTOCOL MANAGER (halmos_http1_manager.c)
    halmos_protocol_t proto = bridge_detect(sock_client, ssl);

    if (proto == PROTOCOL_RETRY) {
        rearm_epoll_oneshot(sock_client);
        return 1;
    }

    if (proto == PROTOCOL_HTTP1) {
        return handle_http1_session(sock_client, is_actually_tls);
    }

    return 0;
}

/**
 * Deteksi Protokol (Support Plaintext & TLS)
 */
halmos_protocol_t bridge_detect(int fd, SSL *ssl) {
    char buf[4];
    ssize_t n;

    // CCTV 1
    //fprintf(stderr, "[DEBUG-DETECT] Mencoba deteksi protokol pada FD %d...\n", fd);
    // Jika pakai TLS, kita peek lewat OpenSSL
    if (ssl) {
        n = SSL_peek(ssl, buf, 4);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return PROTOCOL_RETRY;
            return PROTOCOL_UNKNOWN;
        }
    } else {
        // Plaintext peek
        n = recv(fd, buf, 4, MSG_PEEK | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return PROTOCOL_RETRY;
            return PROTOCOL_UNKNOWN;
        }
    }

    if (n < 4) {
        //fprintf(stderr, "[DEBUG-DETECT] FD %d: Data kurang dari 4 byte (n=%zd). Retry.\n", fd, n);
        return PROTOCOL_RETRY;
    }
    // Deteksi HTTP Methods

    //fprintf(stderr, "[DEBUG-DETECT] FD %d: 4 byte pertama: [%.4s]\n", fd, buf);
    if (memcmp(buf, "GET ", 4) == 0 || memcmp(buf, "POST", 4) == 0 || 
        memcmp(buf, "HTTP", 4) == 0 || memcmp(buf, "PUT ", 4) == 0 ||
        memcmp(buf, "HEAD", 4) == 0) {
        
        //fprintf(stderr, "[DEBUG-DETECT] FD %d: Terdeteksi HTTP1!\n", fd);
        return PROTOCOL_HTTP1;
    }

    return PROTOCOL_UNKNOWN;
}
