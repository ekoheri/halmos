#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "config.h"
#include "queue.h"

// Variabel Global (Extern agar bisa diakses main.c jika perlu)
extern Config config;
extern TaskQueue global_queue;

/**
 * Mengubah program menjadi proses latar belakang (Daemon).
 */
void set_daemon();
// Prototype Fungsi Utama
void start_server();
void run_server();
void stop_server(int sig);
int handle_client(int sock_client);
void* worker_routine(void* arg);
void set_nonblocking(int sock);

#endif