#include "halmos_fcgi_poller.h"
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
static FCGIAsyncPoller upstream_poller;

// Pointer array events yang dialokasikan secara dinamis berdasarkan g_event_batch_size
static struct epoll_event *g_epoll_events = NULL;

bool halmos_fcgi_poller_init(void) {
    //fprintf(stderr, "[FCGI_POLLER_DEBUG] Initializing upstream epoll poller (batch size: %d)...\n", g_event_batch_size);
    
    upstream_poller.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (upstream_poller.epoll_fd == -1) {
        //fprintf(stderr, "[FCGI_POLLER_DEBUG] ERROR: Failed to create epoll fd: %s\n", strerror(errno));
        return false;
    }

    // Alokasikan memori epoll_event secara dinamis berdasarkan nilai adaptif g_event_batch_size
    g_epoll_events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * g_event_batch_size);
    if (!g_epoll_events) {
        //fprintf(stderr, "[FCGI_POLLER_DEBUG] ERROR: Failed to allocate memory for g_epoll_events!\n");
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
        return false;
    }

    upstream_poller.running = true;

    // Luncurkan thread mandiri untuk poller upstream
    if (pthread_create(&upstream_poller.poller_thread, NULL, halmos_fcgi_poller_routine, NULL) != 0) {
        //fprintf(stderr, "[FCGI_POLLER_DEBUG] ERROR: Failed to create poller thread: %s\n", strerror(errno));
        free(g_epoll_events);
        g_epoll_events = NULL;
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
        return false;
    }

    //fprintf(stderr, "[FCGI_POLLER_DEBUG] Upstream poller initialized & thread started successfully.\n");
    return true;
}

void halmos_fcgi_poller_cleanup(void) {
    //fprintf(stderr, "[FCGI_POLLER_DEBUG] Cleaning up upstream poller...\n");
    upstream_poller.running = false;
    
    if (upstream_poller.epoll_fd != -1) {
        close(upstream_poller.epoll_fd);
        upstream_poller.epoll_fd = -1;
    }

    // Tunggu thread poller selesai
    pthread_join(upstream_poller.poller_thread, NULL);

    // Bebaskan memori alokasi dinamis event batch
    if (g_epoll_events) {
        free(g_epoll_events);
        g_epoll_events = NULL;
    }

    //fprintf(stderr, "[FCGI_POLLER_DEBUG] Poller thread joined and cleaned up.\n");
}

bool halmos_fcgi_poller_add(int fpm_fd, HalmosFCGISession *session, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = session; // Kaitkan event dengan pointer sesi FSM

    // --- DEBUG TAMBAHAN UNTUK MELACAK PENYEBAB EINVAL ---
    //fprintf(stderr, "[POLLER_DIAG] halmos_fcgi_poller_add called: upstream_epoll_fd=%d, fpm_fd=%d, session=%p, events=0x%x\n", 
    //        upstream_poller.epoll_fd, fpm_fd, (void*)session, events);

    if (upstream_poller.epoll_fd < 0) {
        //fprintf(stderr, "[POLLER_DIAG] ERROR: upstream_poller.epoll_fd is invalid (%d)!\n", upstream_poller.epoll_fd);
    }
    
    if (fpm_fd < 0) {
        //fprintf(stderr, "[POLLER_DIAG] ERROR: fpm_fd is invalid (%d)!\n", fpm_fd);
    }

    if (!session) {
        //fprintf(stderr, "[POLLER_DIAG] ERROR: session pointer is NULL!\n");
    }
    // ----------------------------------------------------

    if (epoll_ctl(upstream_poller.epoll_fd, EPOLL_CTL_ADD, fpm_fd, &ev) < 0) {
        //fprintf(stderr, "[POLLER_DIAG] ERROR: epoll_ctl(EPOLL_CTL_ADD) failed! errno=%d (%s)\n", errno, strerror(errno));
        return false;
    }

    //fprintf(stderr, "[POLLER_DIAG] SUCCESS: fpm_fd=%d successfully added to epoll.\n", fpm_fd);
    return true;
}

bool halmos_fcgi_poller_mod(int fpm_fd, uint32_t events) {
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

bool halmos_fcgi_poller_del(int fpm_fd) {
    //fprintf(stderr, "[FCGI_POLLER_DEBUG] Deleting fpm_fd=%d from epoll\n", fpm_fd);
    
    if (epoll_ctl(upstream_poller.epoll_fd, EPOLL_CTL_DEL, fpm_fd, NULL) < 0) {
        // Jika error karena memang sudah tidak ada di epoll (sudah dihapus sebelumnya), 
        // jangan anggap sebagai error fatal. Cukup return true atau abaikan.
        if (errno == ENOENT) {
            //fprintf(stderr, "[FCGI_POLLER_DEBUG] Notice: fpm_fd=%d was already removed from epoll (ignored).\n", fpm_fd);
            return true; 
        }
        
        //fprintf(stderr, "[FCGI_POLLER_DEBUG] ERROR: epoll_ctl DEL failed for fd=%d: %s\n", fpm_fd, strerror(errno));
        return false;
    }
    return true;
}

void* halmos_fcgi_poller_routine(void *arg) {
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
            HalmosFCGISession *session = (HalmosFCGISession*)g_epoll_events[i].data.ptr;
            if (!session) continue;

            uint32_t revents = g_epoll_events[i].events;
            //fprintf(stderr, "[FCGI_POLLER_ROUTINE] Event triggered! session=%p, revents=0x%x\n", (void*)session, revents);

            // 1. Prioritaskan pembacaan data jika ada EPOLLIN atau EPOLLPRI
            if (revents & (EPOLLIN | EPOLLPRI)) {
                //fprintf(stderr, "[FCGI_POLLER_ROUTINE] -> PHP-FPM ready to read. Pushing FCGI_TASK_PROCESS_READ.\n");
                
                if (session->fpm_fd != -1) {
                    halmos_fcgi_poller_del(session->fpm_fd);
                }

                halmos_fcgi_queue_push(session, FCGI_TASK_PROCESS_READ);
            } 
            // 2. Tangani HUP/ERR hanya jika tidak ada data tersisa atau terjadi error murni
            else if (revents & (EPOLLERR | EPOLLHUP)) {
                //fprintf(stderr, "[FCGI_POLLER_ROUTINE] -> PHP-FPM error/HUP detected. Removing fd and pushing DISCONNECT.\n");
                
                if (session->fpm_fd != -1) {
                    halmos_fcgi_poller_del(session->fpm_fd);
                }
                
                halmos_fcgi_queue_push(session, FCGI_TASK_DISCONNECT);
            }
        }
    }

    //fprintf(stderr, "[FCGI_POLLER_ROUTINE] Poller thread stopped.\n");
    return NULL;
}