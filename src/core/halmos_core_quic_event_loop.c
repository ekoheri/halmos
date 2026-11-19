#include "halmos_core_quic_event_loop.h"
#include "halmos_global.h"
#include "halmos_transport_udp_server.h"
#include "halmos_core_quic_conn_table.h"
#include "halmos_core_quic_queue.h"
#include "halmos_core_quic_parser.h"
#include "halmos_sec_quic_tls.h"
#include "halmos_sec_quic_crypto.h"
#include "halmos_core_config.h"
#include "halmos_core_admission.h"
#include "halmos_core_conn_table.h"
#include "halmos_core_queue.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

/* Struktur State Poller QUIC (Mirip FCGI_AsyncEventLoop) */
typedef struct {
    int epoll_fd;
    int sock_server;
    pthread_t event_thread;
    atomic_bool running;
} QuicAsyncEventLoop;

extern QuicConnTable quic_conn_table;

static QuicAsyncEventLoop quic_poller = { .epoll_fd = -1, .sock_server = -1, .event_thread = 0, .running = false };
static struct epoll_event *g_quic_events = NULL;

/* Deklarasi fungsi worker thread */
static void* quic_event_loop_run_thread(void *arg);

bool core_quic_event_loop_start(void) {
    if (core_quic_conn_table_init(&quic_conn_table) != 0) {
        write_log("[QUIC ERROR] Failed to initialize QUIC connection table.");
        return false;
    }

    quic_poller.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (quic_poller.epoll_fd == -1) {
        write_log_error_code(ERR_CORE_EPOLL_CREATE, strerror(errno));
        return false;
    }

    /* Alokasi dinamis event batch berdasarkan adaptive hardware */
    g_quic_events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * adaptive_hw_aware.event_batch_size);
    if (!g_quic_events) {
        write_log_error_code(ERR_CORE_EPOLL_MEM);
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    /* Buat server UDP menggunakan modul Anda */
    quic_poller.sock_server = udp_create_server(config.server_name, config.server_port);
    if (quic_poller.sock_server < 0) {
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    /* Daftarkan socket UDP ke epoll QUIC */
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = quic_poller.sock_server;

    if (epoll_ctl(quic_poller.epoll_fd, EPOLL_CTL_ADD, quic_poller.sock_server, &ev) < 0) {
        write_log_error_code(ERR_CORE_EPOLL_ADD_SOCK, strerror(errno));
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    atomic_store(&quic_poller.running, true);

    /* Luncurkan thread mandiri untuk QUIC poller */
    if (pthread_create(&quic_poller.event_thread, NULL, quic_event_loop_run_thread, NULL) != 0) {
        atomic_store(&quic_poller.running, false);
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    write_log("[QUIC CORE] QUIC Server listening on UDP %s:%d (Thread-based)", config.server_name, config.server_port);
    return true;
}

void core_quic_event_loop_stop(void) {
    atomic_store(&quic_poller.running, false);

    /* 1. Tunggu thread poller selesai TERLEBIH DAHULU */
    if (quic_poller.event_thread) {
        pthread_join(quic_poller.event_thread, NULL);
        quic_poller.event_thread = 0;
    }

    /* 2. Tutup socket server */
    if (quic_poller.sock_server != -1) {
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
    }

    /* 3. Tutup epoll_fd setelah thread benar-benar mati */
    if (quic_poller.epoll_fd != -1) {
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
    }

    /* 4. Bebaskan memori batch events */
    if (g_quic_events) {
        free(g_quic_events);
        g_quic_events = NULL;
    }

    core_quic_conn_table_destroy(&quic_conn_table);
    write_log("[QUIC CORE] QUIC Server stopped and cleaned up safely.");
}

int core_quic_event_loop_get_server_fd(void) {
    return quic_poller.sock_server;
}

static void* quic_event_loop_run_thread(void *arg) {
    (void)arg;
    uint8_t buffer[65535];
    struct sockaddr_in client_addr;

    while (atomic_load(&quic_poller.running)) {
        int n = epoll_wait(quic_poller.epoll_fd, g_quic_events, adaptive_hw_aware.event_batch_size, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            int current_fd = g_quic_events[i].data.fd;

            if (current_fd == quic_poller.sock_server) {
                while (atomic_load(&quic_poller.running)) {
                    socklen_t addr_len = sizeof(client_addr);
                    memset(&client_addr, 0, sizeof(client_addr));

                    ssize_t nbytes = recvfrom(quic_poller.sock_server, buffer, sizeof(buffer), 0,
                                              (struct sockaddr *)&client_addr, &addr_len);

                    if (nbytes < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        break;
                    }
                    if (nbytes == 0) break;

                    if (quic_conn_table.total_connections >= (size_t)adaptive_hw_aware.worker_max) {
                        continue;
                    }

                    uint8_t dcid_buffer[MAX_DCID_LEN];
                    uint8_t dcid_len = 0;
                    bool has_dcid = false;
                    bool is_long_header = (buffer[0] & 0x80) != 0;

                    if (is_long_header) {
                        if (core_quic_parser_extract_dcid(buffer, (size_t)nbytes, dcid_buffer, &dcid_len) == 0 && dcid_len > 0) {
                            has_dcid = true;
                        } else {
                            continue;
                        }
                    } else {
                        size_t default_dcid_len = 8;
                        if ((size_t)nbytes > (1 + default_dcid_len) && default_dcid_len <= MAX_DCID_LEN) {
                            memcpy(dcid_buffer, buffer + 1, default_dcid_len);
                            dcid_len = (uint8_t)default_dcid_len;
                            has_dcid = true;
                        } else {
                            continue;
                        }
                    }

                    core_quic_queue_push(
                        &quic_global_queue,
                        buffer,
                        (size_t)nbytes,
                        &client_addr,
                        addr_len,
                        dcid_buffer,
                        dcid_len,
                        has_dcid,
                        is_long_header
                    );
                }
            }
        }
    }

    return NULL;
}

  
