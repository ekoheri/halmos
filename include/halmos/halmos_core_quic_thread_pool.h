#ifndef HALMOS_CORE_QUIC_THREAD_POOL_H
#define HALMOS_CORE_QUIC_THREAD_POOL_H

#include <pthread.h>

void core_quic_thread_pool_start(void);
void core_quic_thread_pool_stop(void);
int core_quic_thread_pool_spawn_workers(int count);
void *core_quic_thread_pool_worker(void *arg);

#endif /* HALMOS_CORE_QUIC_THREAD_POOL_H */