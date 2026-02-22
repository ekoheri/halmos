#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_adaptive.h"
#include "halmos_event_loop.h"
#include "halmos_queue.h"
#include "halmos_thread_pool.h"
#include "halmos_log.h"
#include "halmos_config.h"
#include "halmos_security.h"
#include "halmos_fcgi.h"
#include "halmos_tls.h"
#include "halmos_websocket.h"
#include "halmos_ws_config.h"


#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>

// Fungsi biar kalau di-CTRL+C, server mati dengan sopan
void setup_signals() {
    signal(SIGPIPE, SIG_IGN);  // Abaikan koneksi putus tiba-tiba
    signal(SIGTERM, stop_event_loop);
    signal(SIGINT, stop_event_loop);
}

int main() {
    setup_signals();

    load_config("/etc/halmos/halmos.conf");
    halmos_ws_config_load("/etc/halmos/ws_proto.json");

    halmos_adaptive_init_all();

    // 2. Aktifkan Logger Asynchronous (Thread Terpisah)
    start_thread_logger();

    // 3. Inisialisasi Layanan Global (PINDAHAN DARI EVENT LOOP)
    if (config.tls_enabled) {
        init_openssl_runtime();
        // Mapping FD ke SSL (Ukuran g_queue_capacity + buffer aman)
        init_ssl_mapping(g_queue_capacity + 2000); 
        write_log("[INIT] TLS Engine & Mapping ready.");
    }
    
    // Inisialisasi Registry & Hash Table WebSocket
    halmos_ws_system_init();
    write_log("[INIT] WebSocket Registry & Subsystems ready.");

    // 4. Inisialisasi Antrean (Dapur) & Thread Pool Dinamis
    // Menggunakan batas antrean dari config
    start_thread_worker();

    if(config.rate_limit_enabled == true) {
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

    stop_thread_logger();
    
    halmos_ws_system_destroy();
    // bersihkan resource SSL jika aktif
    if (config.tls_enabled) {
        cleanup_openssl();
        write_log("[CORE] TLS Resources cleaned up.");
    }
    return 0;
}