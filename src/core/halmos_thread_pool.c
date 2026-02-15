#include "halmos_thread_pool.h"
#include "halmos_global.h"
#include "halmos_http_bridge.h"
#include "halmos_log.h"
#include "halmos_security.h"
#include "halmos_event_loop.h"

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

void mark_worker_idle(TaskQueue *q);

/********************************************************************
 * halmos_worker_routine() -> [SIKLUS KERJA KOKI]
 * Persis Logika Boss: Ambil -> Masak -> Beresin Meja
 ********************************************************************/
void *worker_thread_pool(void *arg){
    (void)arg;
    while (1) {
        struct timeval arrival;
        
        // 1. Ambil tugas dari antrean (Block di sini jika kosong)
        // Dequeue sudah menangani pthread_cond_wait internal
        int sock_client = dequeue(&global_queue, &arrival);

        // --- [ LOGIKA TLS START ] ---
        if (config.tls_enabled) {
            SSL *ssl = get_ssl_for_fd(sock_client); 
            if (ssl) {
                if (!SSL_is_init_finished(ssl)) {
                    int r = SSL_accept(ssl);
                    if (r <= 0) {
                        int err = SSL_get_error(ssl, r);
                        
                        // 1. Cek dulu apakah ini cuma masalah koneksi Non-Blocking
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            rearm_epoll_oneshot(sock_client);
                            mark_worker_idle(&global_queue);
                            continue; // Balik ke dequeue, tunggu epoll panggil lagi
                        }
                        
                        // 2. Jika ERROR beneran, cek apakah dia ngomong HTTP (Reason 156)
                        unsigned long l_err = ERR_peek_last_error();
                        if (ERR_GET_REASON(l_err) == 156 || ERR_GET_REASON(l_err) == SSL_R_HTTP_REQUEST) {
                            // Cetak log biar kita tahu si Worker berhasil nangkep basah
                            write_log("[SEC] Plain HTTP detected in Worker on FD %d. Sending 400.", sock_client);
                            
                            char *msg = "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n\r\n"
                                "<html><head><title>400 Bad Request</title></head>"
                                "<body style='font-family:sans-serif; text-align:center; padding-top:50px;'>"
                                "<h1>HTTPS Required</h1>"
                                "<p>Halmos Server only accepts <b>HTTPS</b> connections, Boss!</p>"
                                "<hr><i style='color:gray;'>Halmos Core Engine</i>"
                                "</body></html>";
                            send(sock_client, msg, strlen(msg), 0);
                        }
                        
                        // 3. Beresin SSL dan Socket
                        handle_connection_error(sock_client, ssl);
                        continue; 
                    }
                }
            } else {
                // Kondisi hantu: TLS aktif tapi objek SSL nggak ada
                write_log_error("[SEC] Ghost SSL object on FD %d", sock_client);
                close(sock_client);
                global_telemetry.active_connections--;
                mark_worker_idle(&global_queue);
                continue;
            }
        } else if (!config.tls_enabled) {
            unsigned char buffer[2];
            // Intip cuma 2 byte cukup buat deteksi TLS (0x16 0x03)
            ssize_t n = recv(sock_client, buffer, 2, MSG_PEEK | MSG_DONTWAIT);
            
            if (n == 2 && buffer[0] == 0x16 && buffer[1] == 0x03) {
                write_log("[SEC] HTTPS Handshake detected on HTTP port. FD: %d", sock_client);
                
                // Kirim pesan (meskipun browser mungkin menolak nampilin)
                char *msg = "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: text/plain\r\n"
                            "Connection: close\r\n\r\n"
                            "This server only speaks HTTP, Boss!";
                send(sock_client, msg, strlen(msg), 0);

                // Langsung beresin
                close(sock_client); 
                global_telemetry.active_connections--;
                mark_worker_idle(&global_queue);
                continue; 
            }
        }
        // --- [ LOGIKA TLS END ] ---

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        if (sock_client < 0) continue;
        
        global_telemetry.total_requests++;

        // 2. Proses Request (Bisa HTML, PHP, Rust atau Python)
        // Panggil bridge_dispatch dari halmos_http_bridge.c 

        if (bridge_dispatch(sock_client) == 1) {
            // Jika Keep-Alive: Re-arm EPOLL
            struct epoll_event ev;
            // TAMBAHKAN EPOLLET DI SINI JUGA!
            ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
            ev.data.fd = sock_client;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock_client, &ev) == -1) {
                write_log_error("[WORKER] Failed to re-arm epoll for FD %d: %s", sock_client, strerror(errno));
                global_telemetry.active_connections--;
                close(sock_client);
            }
        } else {
            // --- [ LOGIKA TLS CLEANUP ] ---
            if (config.tls_enabled) {
                SSL *ssl = get_ssl_for_fd(sock_client);
                if (ssl) {
                    SSL_shutdown(ssl);            // Kirim salam perpisahan ke browser
                    nullify_ssl_ptr(sock_client); // Hapus dari tabel mapping
                    SSL_free(ssl);                // Bebaskan RAM
                }
            }
            // ------------------------------
            global_telemetry.active_connections--; // Tamu pulang
            /*
            PAKSA SHUTDOWN SEBELUM CLOSE Ini kunci biar ab nggak timeout!
            Gara-gara lupa gak shutdown, apacche bechmark (ab) jadi ngadat!

            Kenapa shutdown itu Penting?
            Kalau lo cuma pakai close(), kamu cuma nutup pintu 
            dari sisi lo, tapi kernel nggak selalu langsung kirim paket FIN (selesai) 
            ke arah ab atau browser kalau masih ada data di buffer.
            */
            shutdown(sock_client, SHUT_WR); 
            
            // Buang sisa data junk dari client kalau ada
            char junk[1024];
            while(recv(sock_client, junk, sizeof(junk), MSG_DONTWAIT) > 0);

            // 3. Langsung tutup
            close(sock_client);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);   // SELESAI UKUR

        // --- SETOR KE TELEMETRY ---
        global_telemetry.last_latency_ms = hitung_durasi(start, end);
        
        // Update RAM setiap 100 request agar tidak membebani CPU
        if (global_telemetry.total_requests % 100 == 0) {
            update_mem_usage();
        }

        // Tulis ke log asinkron
        write_log_telemetry();

        // 3. Selesai proses, tandai thread kembali IDLE
        mark_worker_idle(&global_queue);
    }
    return NULL;
}

/********************************************************************
 * mark_worker_idle()
 * ---------------------------------------------------------------
 * Analogi:
 * Setelah koki selesai masak:
 *
 * Dia laporan ke manajer:
 * "Saya sudah selesai, siap terima pesanan lagi."
 *
 * Status active_workers dikurangi satu.
 ********************************************************************/
void mark_worker_idle(TaskQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->active_workers--;
    pthread_mutex_unlock(&q->lock);
}
