#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_queue.h"
#include "halmos_event_loop.h"
#include "halmos_thread_pool.h"
#include "halmos_log.h"
#include "halmos_config.h"
#include "halmos_security.h"
#include "halmos_fcgi.h"

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>

Config config;

// Fungsi biar kalau di-CTRL+C, server mati dengan sopan
void setup_signals() {
    signal(SIGPIPE, SIG_IGN);  // Abaikan koneksi putus tiba-tiba
    signal(SIGTERM, stop_event_loop);
    signal(SIGINT, stop_event_loop);
}

int main() {
    setup_signals();

    load_config("/etc/halmos/halmos.conf");

    // 2. Aktifkan Logger Asynchronous (Thread Terpisah)
    start_thread_logger();

    // 4. Inisialisasi Antrean (Dapur) & Thread Pool Dinamis
    // Menggunakan batas antrean dari config
    start_thread_worker();

    if(config.rate_limit_enabled) {
        start_janitor();    
    }
    
    halmos_fcgi_pool_init();

    //halmos_fcgi_pool_init(&php_pool, config.php_server);
    //halmos_fcgi_pool_init(&rust_pool, config.rust_server, config.rust_port);

    // 6. Inisialisasi Server (Network & Epoll)
    // Memanggil halmos_server_init yang sudah kita integrasikan dengan network.c
    start_event_loop();

    /*
    printf("==================================================\n");
    printf("  HALMOS SAVAGE SERVER IS RUNNING\n");
    printf("  Address : %s:%d\n", config.server_name, config.server_port);
    printf("  Root    : %s\n", config.document_root);
    printf("==================================================\n");
    */
   
    // 7. RUN! Masuk ke Loop Utama (Resepsionis Epoll)
    run_event_loop();

    return 0;
}
