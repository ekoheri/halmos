#ifndef HALMOS_THREAD_POOL_H
#define HALMOS_THREAD_POOL_H


// Fungsi yang dijalankan oleh thread di thread pool
void *worker_thread_pool(void *arg);

void start_thread_worker();
#endif