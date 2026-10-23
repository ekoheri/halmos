#ifndef HALMOS_FCGI_EVENT_LOOP_H
#define HALMOS_FCGI_EVENT_LOOP_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "halmos_fcgi_session.h"

typedef struct {
    int epoll_fd;               // File descriptor instance epoll mandiri untuk upstream
    pthread_t event_thread;     // Thread mandiri yang menjalankan epoll_wait loop
    volatile bool running;      // Status kontrol untuk menghentikan poller secara aman (graceful stop)
} FCGI_AsyncEventLoop;

bool fcgi_event_loop_start(void);

void* fcgi_event_loop_run(void *arg);

void fcgi_event_loop_stop(void);

bool fcgi_event_loop_add(int fpm_fd, FCGI_Session *session, uint32_t events);

bool fcgi_event_loop_mod(int fpm_fd, uint32_t events);

bool fcgi_event_loop_del(int fpm_fd);

#endif // HALMOS_FCGI_EVENT_LOOP_H