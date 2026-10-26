#include "halmos_fcgi_event_loop.h"
#include "halmos_fcgi_queue.h"
#include "halmos_log.h"
#include "halmos_global.h" 
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Variabel global state poller upstream
static FCGI_AsyncEventLoop upstream_poller;

// Pointer array events yang dialokasikan secara dinamis berdasarkan g_event_batch_size
static struct epoll_event *g_epoll_events = NULL;

bool fcgi_event_loop_start(void) {
    upstream_poller.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (upstream_poller.epoll_fd == -1) {
        write_log_error_code(ERR_FCGI_EPOLL_CREATE, strerror(errno));
        return false;
    }

    // Alokasikan memori epoll_event secara dinamis berdasarkan nilai adaptif g_event_batch_size
    g_epoll_events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * g_event_batch_size);
    if (!g_epoll_events) {
        write_log_error_code(ERR_FCGI_EPOLL_MEM);
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
        return false;
    }

    upstream_poller.running = true;

    // Luncurkan thread mandiri untuk poller upstream
    if (pthread_create(&upstream_poller.event_thread, NULL, fcgi_event_loop_run, NULL) != 0) {
        free(g_epoll_events);
        g_epoll_events = NULL;
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
        return false;
    }

    return true;
}

void fcgi_event_loop_stop(void) {
    upstream_poller.running = false;
    
    if (upstream_poller.epoll_fd != -1) {
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
    }

    // Tunggu thread poller selesai
    pthread_join(upstream_poller.event_thread, NULL);

    // Bebaskan memori alokasi dinamis event batch
    if (g_epoll_events) {
        free(g_epoll_events);
        g_epoll_events = NULL;
    }
}

bool fcgi_event_loop_add(int fpm_fd, FCGI_Session *session, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = session; // Kaitkan event dengan pointer sesi FSM

    if (upstream_poller.epoll_fd < 0 || fpm_fd < 0 || !session) {
        return false;
    }
    
    if (epoll_ctl(upstream_poller.epoll_fd, EPOLL_CTL_ADD, fpm_fd, &ev) < 0) {
        write_log_error_code(ERR_FCGI_EPOLL_ADD, fpm_fd, strerror(errno));
        return false;
    }

    return true;
}

bool fcgi_event_loop_mod(int fpm_fd, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    
    //(stderr, "[FCGI_POLLER_DEBUG] Modifying fpm_fd=%d in epoll (new events=0x%x)\n", fpm_fd, events);

    if (epoll_ctl(upstream_poller.epoll_fd, EPOLL_CTL_MOD, fpm_fd, &ev) < 0) {
        //fprintf(stderr, "[FCGI_POLLER_DEBUG] ERROR: epoll_ctl MOD failed for fd=%d: %s\n", fpm_fd, strerror(errno));
        return false;
    }
    return true;
}
bool fcgi_event_loop_del(int fpm_fd) {
    if (fpm_fd < 0) return false;
    
    // Berikan struct kosong secara eksplisit untuk mencegah bug pointer dangling di kernel lama
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    
    if (epoll_ctl(upstream_poller.epoll_fd, EPOLL_CTL_DEL, fpm_fd, &ev) < 0) {
        if (errno == ENOENT || errno == EBADF) {
            // ENOENT = sudah dihapus, EBADF = descriptor sudah ditutup/tidak valid
            return true; 
        }
        return false;
    }
    return true;
}

void* fcgi_event_loop_run(void *arg) {
    (void)arg;

    //fprintf(stderr, "[FCGI_POLLER_ROUTINE] Poller worker thread running loop (adaptive batch size: %d)...\n", g_event_batch_size);

    while (upstream_poller.running) {
        // Menggunakan g_event_batch_size hasil kalkulasi adaptive hardware
        int n = epoll_wait(upstream_poller.epoll_fd, g_epoll_events, g_event_batch_size, 1000); // Timeout 1 detik
        if (n < 0) {
            if (errno == EINTR) continue;
            //fprintf(stderr, "[FCGI_POLLER_ROUTINE] ERROR: epoll_wait returned error: %s\n", strerror(errno));
            break; // Fatal error pada epoll
        }

        for (int i = 0; i < n; i++) {
            FCGI_Session *session = (FCGI_Session*)g_epoll_events[i].data.ptr;
            if (!session) continue;

            uint32_t revents = g_epoll_events[i].events;
            //fprintf(stderr, "[FCGI_POLLER_ROUTINE] Event triggered! session=%p, revents=0x%x\n", (void*)session, revents);

            // 1. Prioritaskan pembacaan data jika ada EPOLLIN atau EPOLLPRI
            if (revents & (EPOLLIN | EPOLLPRI)) {
                //fprintf(stderr, "[FCGI_POLLER_ROUTINE] -> PHP-FPM ready to read. Pushing FCGI_TASK_PROCESS_READ.\n");
                
                if (session->fpm_fd != -1) {
                    fcgi_event_loop_del(session->fpm_fd);
                }

                fcgi_queue_push(session, FCGI_TASK_PROCESS_READ);
            } 
            // 2. Tangani HUP/ERR hanya jika tidak ada data tersisa atau terjadi error murni
            else if (revents & (EPOLLERR | EPOLLHUP)) {
                //fprintf(stderr, "[FCGI_POLLER_ROUTINE] -> PHP-FPM error/HUP detected. Removing fd and pushing DISCONNECT.\n");
                
                if (session->fpm_fd != -1) {
                    fcgi_event_loop_del(session->fpm_fd);
                }
                
                fcgi_queue_push(session, FCGI_TASK_DISCONNECT);
            }
        }
    }

    //fprintf(stderr, "[FCGI_POLLER_ROUTINE] Poller thread stopped.\n");
    return NULL;
}