#ifndef HALMOS_CORE_EVENT_LOOP_H
#define HALMOS_CORE_EVENT_LOOP_H

#include "halmos_core_config.h"
#include "halmos_core_queue.h"

#define NUM_QUEUES 4

void event_loop_start();
void event_loop_run();
void event_loop_stop(int sig);

//dipanggil di thread pool dan bridge
void event_loop_rearm_epoll(int fd); 
void event_loop_cleanup_connection(int sock_client);
#endif
