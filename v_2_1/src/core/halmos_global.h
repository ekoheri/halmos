#ifndef HALMOS_GLOBAL_H
#define HALMOS_GLOBAL_H

#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_queue.h"

// Deklarasikan variabel global untuk :
// 1. menyimpan konfigurasi
extern Config config;

// 2. menyimpan informasi struct event pool
extern struct epoll_event *events;

// 3. menyimoan flag data event pool
extern int epoll_fd;

// 4. menyimpan informasi jumlah maksimum event loop
// sesuaidengan kapasitas Core CPU komputer
extern int max_event_loop;

// 5. Informasi menyimpan taskqueue
extern TaskQueue global_queue;

// 6. Forward declaration untukworker_thread_pool 
// yang ada di halmos_queue.c
extern void *worker_thread_pool(void *arg);

#endif