#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "../include/core/web_server.h"
#include "../include/core/config.h"
#include "../include/core/log.h"
#include "../include/core/queue.h"

// Inisialisasi variabel global dari web_server
Config config;
TaskQueue global_queue;

int main() {
    // Abaikan SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);

    // 1. Load Config
    load_config("/etc/halmos/halmos.conf");
    
    // 2. Deteksi Core & Setup Thread Pool
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    int dynamic_min = (int)num_cores * 2;
    int dynamic_max = (int)num_cores * 8;

    init_queue(&global_queue, dynamic_min, dynamic_max);

    write_log("Halmos Engine Started. Core: %ld. Dynamic Pool: %d-%d", 
              num_cores, dynamic_min, dynamic_max);

    // 3. Jalankan Worker Threads
    for (int i = 0; i < global_queue.total_workers; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, worker_routine, &global_queue);
        pthread_detach(tid);
    }

    // 4. Bind & Listen
    start_server();

    // 5. Enter Event Loop
    run_server();

    return 0;
}