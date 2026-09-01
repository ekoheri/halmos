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
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_ws_system.h"


#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>

// Handle sinyal dengan aman (Async-Signal Safe)
static void handle_shutdown_signal(int sig) {
    (void)sig;
    event_loop_stop(); // Hentikan loop epoll_wait agar keluar dari event_loop_run()
}

void setup_signals(void) {
    struct sigaction sa;
    sa.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    signal(SIGPIPE, SIG_IGN); // Abaikan koneksi yang putus mendadak
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

int main() {
    setup_signals();

    // 1. Load Konfigurasi (Log ke stderr jika gagal sebelum logger aktif)
    if(core_config_load("/etc/halmos/halmos.conf") != 0){
        return EXIT_FAILURE;
    }

    core_adaptive_init();

    // 2. Aktifkan Logger Asynchronous (Thread Terpisah)
    start_thread_logger();
    write_log("[CORE] Starting Halmos Web Server v1.0.0-rc1...");

    // 3. Inisialisasi Layanan SSL
    if (config.tls_enabled) {
        if(ssl_init() != 0) {
            fprintf(stderr, "[FATAL] Failed to initialize SSL Engine.\n");
            stop_thread_logger();
            return EXIT_FAILURE;
        }
        // Mapping FD ke SSL (Ukuran g_queue_capacity + buffer aman)
        ssl_init_mapping(g_queue_capacity + 2000); 
        write_log("[CORE] TLS Engine & Mapping ready.");
    }
    
    // Inisialisasi Virtual Host
    http_vhost_init_all();

    // Inisialisasi Registry & Hash Table WebSocket
    halmos_ws_system_init();
    write_log("[CORE] WebSocket Registry & Subsystems ready.");

    // 4. Inisialisasi Antrean (Dapur) & Thread Pool Dinamis
    // Menggunakan batas antrean dari config
    queue_thread_worker_start();

    if(config.rate_limit_enabled == true) {
        sec_traffic_start_janitor();    
    }
    
    fcgi_pool_init();

    // 5. Inisialisasi Server (Network & Epoll)
    if (event_loop_start() != 0) {
        fprintf(stderr, "[FATAL] Failed to start event loop.\n");
        stop_thread_logger();
        return EXIT_FAILURE;
    }

    /*
    printf("==================================================\n");
    printf("  HALMOS SAVAGE SERVER IS RUNNING\n");
    printf("  Address : %s:%d\n", config.server_name, config.server_port);
    printf("  Root    : %s\n", config.document_root);
    printf("==================================================\n");
    */
   
    // 6. RUN! Resepsionis Epoll Utama
    event_loop_run();

    // =======================================================
    // --- GRACEFUL SHUTDOWN CLEANUP SEQUENCE ---
    // =======================================================
    
    write_log("[CORE] Shutdown signal caught. Cleaning up resources...");
    
    // 2. Stop Worker Thread Pool & Join semua thread
    queue_thread_worker_stop();
    write_log("[CORE] Worker thread pool joined & stopped.");

    // Stop Janitor Security Thread
    if (config.rate_limit_enabled) {
        sec_traffic_stop_janitor();
    }
    
    // 2. Hancurkan FastCGI Connection Pool (Tutup socket & free memory)
    fcgi_pool_destroy();
    write_log("[CORE] FastCGI Connection Pool destroyed.");
    
    ws_system_destroy();
    write_log("[CORE] WebSocket Registry & Subsystems destroyed.");
    // bersihkan resource SSL jika aktif
    if (config.tls_enabled) {
        ssl_cleanup();
        write_log("[CORE] TLS Resources cleaned up.");
    }
   
        // 5. TERAKHIR: Wajib tempatkan stop_thread_logger() di paling ujung!
    // Ini mengosongkan antrean memori log ke file disk sebelum proses exit.
    write_log("[CORE] Halmos shutdown complete. Bye!");
    stop_thread_logger();

    return EXIT_SUCCESS;
}