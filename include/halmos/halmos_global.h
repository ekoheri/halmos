#ifndef HALMOS_GLOBAL_H
#define HALMOS_GLOBAL_H

#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_queue.h"

#include <stdint.h>

// 1. Penampung Hasil Adaptive 
extern AdaptiveHardwareAware adaptive_hw_aware;

// Deklarasikan variabel global untuk :
// 2 menyimpan konfigurasi
extern Config config;

// 3. menyimpan informasi struct event pool
extern struct epoll_event *events;

// 4. menyimpan flag data event pool
extern int epoll_fd;

// 5. Informasi menyimpan taskqueue
extern TaskQueue global_queue;

#endif