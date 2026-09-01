#ifndef HALMOS_CORE_EVENT_LOOP_H
#define HALMOS_CORE_EVENT_LOOP_H

#include "halmos_core_config.h"
#include "halmos_core_queue.h"

#include <stdint.h>

#define NUM_QUEUES 4

int event_loop_start();
void event_loop_run();
void event_loop_stop(void);

//dipanggil di thread pool dan bridge
void event_loop_rearm_epoll(int fd); 
void event_loop_rearm_epoll_ex(int fd, uint32_t events_mask);
void event_loop_cleanup_connection(int sock_client);
#endif
