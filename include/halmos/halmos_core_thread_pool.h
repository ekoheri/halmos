#ifndef HALMOS_CORE_THREAD_POOL_H
#define HALMOS_CORE_THREAD_POOL_H


// Fungsi yang dijalankan oleh thread di thread pool

void core_thread_pool_start(void);
void core_thread_pool_stop(void);
int core_thread_pool_spawn_workers(int count);
void *core_thread_pool_worker(void *arg);

#endif