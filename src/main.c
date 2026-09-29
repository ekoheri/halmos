#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_conn_table.h"
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

#include <string.h>
#include <unistd.h>

// Definisi Identitas & Konfigurasi Global
#define HALMOS_NAME       "Halmos Web Server"
#define HALMOS_VERSION    "1.0.0-RC1"
#define HALMOS_CONFIG_PATH "/etc/halmos/halmos.conf"

// Handle sinyal dengan aman (Async-Signal Safe)
static void handle_shutdown_signal(int sig) {
    (void)sig;
    core_event_loop_stop(); // Hentikan loop epoll_wait agar keluar dari core_event_loop_run()
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

int main(int argc, char *argv[]) {
    // 0. Tangani Argumen CLI (Version, Help, Test Config)
    if (argc > 1) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("%s v%s\n", HALMOS_NAME, HALMOS_VERSION);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("%s v%s\n", HALMOS_NAME, HALMOS_VERSION);
            printf("Usage:\n  halmos [option]\n\n");
            printf("Options:\n");
            printf("  -t, --test       Test configuration file syntax and exit\n");
            printf("  -v, --version    Output version information and exit\n");
            printf("  -h, --help       Display this help and exit\n\n");
            printf("Configuration:\n");
            printf("  Config file is loaded from: %s\n", HALMOS_CONFIG_PATH);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--test") == 0) {
            // 1. Load konfigurasi utama Halmos
            if (core_config_load(HALMOS_CONFIG_PATH) != 0) {
                fprintf(stderr, "[ERROR] Configuration test FAILED: Cannot parse %s\n", HALMOS_CONFIG_PATH);
                return EXIT_FAILURE;
            }
            printf("[OK] Halmos config syntax: %s\n", HALMOS_CONFIG_PATH);

            // 2. Cek Network (Binding IP & Port)
            printf("[OK] Network binding: %s:%d\n", config.server_name, config.server_port);

            // 3. Cek Document Root (Apakah foldernya ada secara fisik)
            if (access(config.document_root, F_OK) == 0) {
                printf("[OK] Document root: %s (Exists)\n", config.document_root);
            } else {
                fprintf(stderr, "[WARN] Document root path not found: %s\n", config.document_root);
            }

            // 4. Cek TLS / SSL Certificates (Jika aktif)
            if (config.tls_enabled) {
                int tls_ok = 1;
                if (access(config.ssl_certificate_file, R_OK) != 0) {
                    fprintf(stderr, "[ERROR] SSL Certificate missing or unreadable: %s\n", config.ssl_certificate_file);
                    tls_ok = 0;
                }
                if (access(config.ssl_private_key_file, F_OK) != 0) {
                    fprintf(stderr, "[ERROR] SSL Private Key file not found: %s\n", config.ssl_private_key_file);
                    tls_ok = 0;
                }
                if (tls_ok) {
                    printf("[OK] TLS Engine: Enabled (Cert & Key valid)\n");
                } else {
                    return EXIT_FAILURE;
                }
            } else {
                printf("[INFO] TLS Engine: Disabled (HTTP Mode)\n");
            }

            // 5. Cek PHP-FPM Config Path (Untuk audit adaptive)
            if (config.php_fpm_config_path[0] != '\0') {
                if (access(config.php_fpm_config_path, R_OK) == 0) {
                    printf("[OK] PHP-FPM config path: %s (Found & Readable)\n", config.php_fpm_config_path);
                } else {
                    fprintf(stderr, "[WARN] PHP-FPM config path NOT FOUND or unreadable: %s\n", config.php_fpm_config_path);
                    fprintf(stderr, "       Hint: Check if PHP-FPM is installed or if the path/permissions are correct.\n");
                }
            } else {
                printf("[WARN] php_fpm_config_path is empty in configuration.\n");
            }

            printf("\nConfiguration test SUCCESSFUL.\n");
            printf("Please adjust the %s configuration before running the web server.\n", config.php_fpm_config_path);
            return EXIT_SUCCESS;
        }
    }

    setup_signals();

    // 1. Load Konfigurasi (Log ke stderr jika gagal sebelum logger aktif)
    if(core_config_load("/etc/halmos/halmos.conf") != 0){
        return EXIT_FAILURE;
    }

    // 2. Hitung Parameter Hardware & OS Limit
    core_adaptive_init();

    // 3. INIALISASI KONEKSI (Menggunakan g_max_fd hasil kalkulasi adaptive)
    if (core_conn_t_init() != 0) {
        fprintf(stderr, "[FATAL] Failed to allocate core connection tracking table.\n");
        return EXIT_FAILURE;
    }

    // 4. Aktifkan Logger Asynchronous (Thread Terpisah)
    start_thread_logger();
    write_log("[CORE] Starting Halmos Web Server v1.0.0-rc1...");

    // 5. Inisialisasi Layanan SSL
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
    core_queue_thread_worker_start();

    if(config.rate_limit_enabled == true) {
        sec_traffic_start_janitor();    
    }
    
    fcgi_pool_init();

    // 5. Inisialisasi Server (Network & Epoll)
    if (core_event_loop_start() != 0) {
        fprintf(stderr, "[FATAL] Failed to start event loop.\n");
        stop_thread_logger();
        return EXIT_FAILURE;
    }

    // === TAMBAHKAN INI DI SINI ===
    // Karena epoll_fd sudah tercipta di dalam core_event_loop_start(), 
    // kita bisa langsung mendaftarkan inotify vhost ke epoll utama.
    // (Asumsikan epoll_fd bisa diakses secara global atau diekspos via getter)
    extern int epoll_fd; // Jika epoll_fd dideklarasikan global di core event loop
    http_vhost_init_inotify(epoll_fd);
    
    /*
    printf("==================================================\n");
    printf("  HALMOS SAVAGE SERVER IS RUNNING\n");
    printf("  Address : %s:%d\n", config.server_name, config.server_port);
    printf("  Root    : %s\n", config.document_root);
    printf("==================================================\n");
    */
   
    // 6. RUN! Resepsionis Epoll Utama
    core_event_loop_run();

    // =======================================================
    // --- GRACEFUL SHUTDOWN CLEANUP SEQUENCE ---
    // =======================================================
    
    write_log("[CORE] Shutdown signal caught. Cleaning up resources...");
    
    // 2. Stop Worker Thread Pool & Join semua thread
    core_queue_thread_worker_stop();
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
   
    // DESTROY CORE CONNECTION TABLE (Simetris dengan core_conn_t_init)
    core_conn_t_destroy();
    write_log("[CORE] Connection Table destroyed.");

    // 5. TERAKHIR: Wajib tempatkan stop_thread_logger() di paling ujung!
    // Ini mengosongkan antrean memori log ke file disk sebelum proses exit.
    write_log("[CORE] Halmos shutdown complete. Bye!");
    stop_thread_logger();

    return EXIT_SUCCESS;
}