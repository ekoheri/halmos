#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
 
#include "halmos_global.h"
#include "halmos_core_config.h" 
#include "halmos_http1_manager.h"
#include "halmos_http2_manager.h"
#include "halmos_http_bridge.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_conn_table.h"
#include "halmos_log.h"
#include "halmos_sec_tls.h"
#include "halmos_ws_system.h"
 
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/epoll.h>
 
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
 
// === TAMBAHAN: deklarasi destructor session, dipakai untuk mengenali
// protokol mana yang sedang aktif pada suatu koneksi (lihat penjelasan
// di http_bridge_dispatch di bawah). Idealnya dideklarasikan resmi di
// halmos_http1_manager.h/halmos_http2_manager.h - extern di sini dulu
// sebagai stopgap.
extern void http1_session_destroy(void *session);
extern void http2_session_destroy(void *session);
 
static halmos_protocol_t bridge_detect(int fd, SSL *ssl);
 
/**
 * Multiplexer Utama: Jembatan antara Core FD dan Protocol Manager
 *
 * Kontrak status kembalian:
 *   0  = selesai / tutup koneksi
 *  -1  = error
 *   1  = keep-alive / butuh I/O lagi, rearm generik EPOLLIN|EPOLLOUT
 *        (dipakai http1_manager_session/http2_manager_session)
 *   2  = butuh BACA lagi saja -> caller rearm EPOLLIN saja
 *   3  = butuh TULIS lagi saja -> caller rearm EPOLLOUT saja
 * (2 & 3 mencegah busy-loop di edge-triggered epoll: rearm spesifik
 *  tidak boleh ketimpa rearm generik EPOLLIN|EPOLLOUT di caller)
 */
int http_bridge_dispatch(int sock_client, uint32_t events) {
    if (halmos_is_websocket_fd(sock_client)) {
        return ws_system_dispatch(sock_client);
    }
 
    halmos_conn_t *conn = core_conn_t_get(sock_client);
    if (!conn) return 0;
 
    // === PERBAIKAN KRITIS: RESUME session yang SUDAH ADA, jangan deteksi ulang ===
    // bridge_detect() di bawah melakukan SSL_peek()/recv(MSG_PEEK) untuk
    // mencari REQUEST BARU dari client - hanya valid untuk koneksi yang
    // BELUM punya protocol_session. Kalau dipanggil lagi saat kita sedang
    // MENULIS response (mis. WANT_WRITE saat kirim file besar, menunggu
    // rearm EPOLLOUT), bridge_detect() salah membaca "tidak ada data BARU
    // dari client" sebagai PROTOCOL_RETRY -> membajak alur jadi rearm
    // EPOLLIN, padahal seharusnya lanjut menulis body yang tertunda.
    // Akibatnya: transfer berhenti permanen di tengah jalan (client dapat
    // data parsial lalu hang - kedua sisi saling menunggu).
    if (conn->protocol_session) {
        if (conn->protocol_session_destroy == http1_session_destroy) {
            return http1_manager_session(conn);
        }
        if (conn->protocol_session_destroy == http2_session_destroy) {
            return http2_manager_session(conn);
        }
        write_log_error("[BRIDGE] Unknown protocol_session destructor on FD %d, closing", sock_client);
        return 0;
    }
 
    char peek_buf[1];
 
    // 1. Ambil state SSL jika ada
    SSL *ssl = ssl_get_for_fd(sock_client);
    bool is_actually_tls = (ssl != NULL);
 
    // Jika event pancingannya adalah EPOLLOUT, kita bisa langsung melompat 
    // ke protocol manager (karena handshake/deteksi awal biasanya sudah selesai di event EPOLLIN sebelumnya).
    if (!(events & EPOLLOUT)) {
        // 2. DETEKSI AWAL: Intip byte pertama kalau belum yakin ini TLS
        if (!is_actually_tls) {
            ssize_t n = recv(sock_client, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
            
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 2; 
                }
                return 0; 
            }
 
            if (n == 0) {
                return 0; // Client close koneksi
            }
 
            if (peek_buf[0] == 0x16) {
                is_actually_tls = true;
                
                if (config.tls_enabled) {
                    ssl = SSL_new(halmos_tls_ctx);
                    SSL_set_fd(ssl, sock_client);
                    ssl_set_for_fd(sock_client, ssl);
                    conn->ssl = ssl;
                }
            }
        }
    }
 
    // 3. EKSEKUSI JALUR TLS
    if (is_actually_tls) {
        if (!config.tls_enabled) {
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
                if (err == SSL_ERROR_WANT_READ) {
                    return 2; 
                } else if (err == SSL_ERROR_WANT_WRITE) {
                    return 3;
                }
                return 0;
            }
        }
    } 
    // 4. EKSEKUSI JALUR PLAIN
    else if (config.tls_enabled) {
        char *msg = "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<html><head><title>400 Bad Request</title></head>"
                    "<body><h1>HTTPS Required</h1><p>Halmos Server only accepts <b>HTTPS</b> connections, Boss!</p></body></html>";
        send(sock_client, msg, strlen(msg), MSG_NOSIGNAL);
        return 0; 
    }
 
    // 5. PENYERAHAN KE PROTOCOL MANAGER (hanya untuk koneksi BARU, belum
    // punya protocol_session - lihat pengecekan resume di paling atas fungsi)
    halmos_protocol_t proto = bridge_detect(sock_client, ssl);
 
    if (proto == PROTOCOL_RETRY) {
        return 2;
    }
 
    if (proto == PROTOCOL_HTTP1) {
        return http1_manager_session(conn);
    }
 
    if (proto == PROTOCOL_HTTP2) {
        return http2_manager_session(conn);
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
        const unsigned char *alpn_proto = NULL;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);
 
        /*
        NON AKTIFKAN INI JIKA HANYA MELAYANI HTTP1
        */
        if (alpn_proto && alpn_len == 2 && memcmp(alpn_proto, "h2", 2) == 0) {
            // write_log_debug("[BRIDGE] ALPN Negotiated: HTTP/2");
            return PROTOCOL_HTTP2;
        }
        /* ===== akhir dari ALPN==============*/
 
        // Jika ALPN gagal atau tidak ada, kita coba peek isinya (siapa tahu client maksa)
        n = SSL_peek(ssl, buf, 4);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return PROTOCOL_RETRY;
            return PROTOCOL_UNKNOWN;
        }
 
        // Paksa return HTTP1 kalau SSL berhasil
        return PROTOCOL_HTTP1;
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
 
    // A. Deteksi HTTP/2 Preface (PRI * HTTP/2.0...)
    // NON AKTIFKAN INI JIKA MEMAKSA HANYA MELAYANI HTTP1
    if (memcmp(buf, "PRI ", 4) == 0) {
        return PROTOCOL_HTTP2;
    }
    // AKHIR DARI DETEKSI HHTP2
    // Deteksi HTTP Methods
 
    // B. Deteksi HTTP/1 Methods (Existing)
    //fprintf(stderr, "[DEBUG-DETECT] FD %d: 4 byte pertama: [%.4s]\n", fd, buf);
    if (memcmp(buf, "GET ", 4) == 0 || memcmp(buf, "POST", 4) == 0 || 
        memcmp(buf, "HTTP", 4) == 0 || memcmp(buf, "PUT ", 4) == 0 ||
        memcmp(buf, "HEAD", 4) == 0) {
        
        //fprintf(stderr, "[DEBUG-DETECT] FD %d: Terdeteksi HTTP1!\n", fd);
        return PROTOCOL_HTTP1;
    }
 
    return PROTOCOL_UNKNOWN;
}
 
