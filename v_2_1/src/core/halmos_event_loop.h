#ifndef HALMOS_EVENT_LOOP_H
#define HALMOS_EVENT_LOOP_H

#include "halmos_config.h"
#include "halmos_queue.h"

#define NUM_QUEUES 4

void start_event_loop();
void run_event_loop();
void stop_event_loop(); 

#endif
