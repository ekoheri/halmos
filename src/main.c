#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_queue.h"
#include "halmos_core_thread_pool.h"
#include "halmos_log.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_fcgi.h"
#include "halmos_ws_system.h"


#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>

// Fungsi biar kalau di-CTRL+C, server mati dengan sopan
void setup_signals() {
    signal(SIGPIPE, SIG_IGN);  // Abaikan koneksi putus tiba-tiba
    signal(SIGTERM, event_loop_stop);
    signal(SIGINT, event_loop_stop);
}

int main() {
    setup_signals();

    core_config_load("/etc/halmos/halmos.conf");

    core_adaptive_init();

    // 2. Aktifkan Logger Asynchronous (Thread Terpisah)
    start_thread_logger();

    // 3. Inisialisasi Layanan Global (PINDAHAN DARI EVENT LOOP)
    if (config.tls_enabled) {
        ssl_init();
        // Mapping FD ke SSL (Ukuran g_queue_capacity + buffer aman)
        ssl_init_mapping(g_queue_capacity + 2000); 
        write_log("[INIT] TLS Engine & Mapping ready.");
    }
    
    // Inisialisasi Registry & Hash Table WebSocket
    halmos_ws_system_init();
    write_log("[INIT] WebSocket Registry & Subsystems ready.");

    // 4. Inisialisasi Antrean (Dapur) & Thread Pool Dinamis
    // Menggunakan batas antrean dari config
    queue_thread_worker_start();

    if(config.rate_limit_enabled == true) {
        sec_traffic_start_janitor();    
    }
    
    fcgi_pool_init();

    // 6. Inisialisasi Server (Network & Epoll)
    // Memanggil halmos_server_init yang sudah kita integrasikan dengan network.c
    event_loop_start();

    /*
    printf("==================================================\n");
    printf("  HALMOS SAVAGE SERVER IS RUNNING\n");
    printf("  Address : %s:%d\n", config.server_name, config.server_port);
    printf("  Root    : %s\n", config.document_root);
    printf("==================================================\n");
    */
   
    // 7. RUN! Masuk ke Loop Utama (Resepsionis Epoll)
    event_loop_run();

    stop_thread_logger();
    
    ws_system_destroy();
    // bersihkan resource SSL jika aktif
    if (config.tls_enabled) {
        ssl_cleanup();
        write_log("[CORE] TLS Resources cleaned up.");
    }
    return 0;
}