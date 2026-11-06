/* ==========================================================================
 * HALMOS WEB SERVER - MAIN ENTRY POINT & ARCHITECTURAL OVERVIEW
 * --------------------------------------------------------------------------
 * TENTANG TEKNOLOGI HALMOS:
 * 
 * Halmos adalah web server dan reverse proxy konkurensi tinggi berbasis C dengan 
 * arsitektur asinkron event-driven (non-blocking I/O). Dirancang untuk mendobrak 
 * batasan konfigurasi statis tradisional, Halmos mengintegrasikan sistem kesadaran 
 * mandiri (hardware-aware adaptive engine) yang secara otonom mengkalibrasi kapasitas 
 * operasionalnya berdasarkan realitas telemetri mesin saat startup.
 * 
 * PILAR ARSITEKTUR UTAMA:
 * 
 * 1. LAPISAN PROTOKOL JARINGAN (HTTP/1.1, HTTP/2, & WEBSOCKET):
 *    - Menyediakan parser dan penangan protokol web modern secara asinkron.
 *    - Mendukung manajemen koneksi persisten HTTP/1.1, multiplexing aliran data 
 *      untuk HTTP/2, serta channel komunikasi real time full-duplex melalui WebSocket.
 * 
 * 2. HARDWARE-AWARE ADAPTIVE INITIALIZATION (halmos_core_adaptive):
 *    - Halmos tidak mengandalkan konfigurasi manual yang kaku, tetapi sistem membaca kondisi 
 *      nyata perangkat keras (Jumlah Core CPU, Total RAM, dan Batasan File Descriptor).
 *    - Secara otomatis menghitung batasan jumlah worker, mengamankan cadangan memori untuk OS/database 
 *      (sebesar 25% dari total RAM), serta menyelaraskan ukuran batch event jaringan.
 * 
 * 3. MULTI-RUNTIME BACKEND POOL & FASTCGI DISPATCHER (halmos_fcgi_pool):
 *    - Bertindak sebagai gateway cerdas yang menjembatani permintaan client ke dalam 
 *      arsitektur hybrid 3 bahasa (PHP, Rust, Python) melalui protokol FastCGI/FPM.
 *    - Melakukan parsing konfigurasi backend secara dinamis (misal membaca pm.max_children 
 *      milik PHP-FPM) serta mendistribusikan sisa kuota worker secara proporsional 
 *      berdasarkan anggaran memori masing-masing proses.
 * 
 * 4. EVENT LOOP, TASK QUEUE, & ADAPTIVE MULTI-THREAD:
 *    - Menerapkan arsitektur multi-thread adaptif di mana jumlah thread dan worker 
 *      diskalakan secara dinamis mengikuti ketersediaan inti prosesor (CPU cores).
 *    - Menggunakan mekanisme polling berbasis event (epoll) untuk menangani 
 *      ribuan deskriptor koneksi konkuren secara asinkron dengan overhead minimal.
 *    - Dilengkapi antrean tugas (Task Queue) berkapasitas adaptif dengan pengaman 
 *      mutlak (MAX_QUEUE_CAPACITY) guna menangkis lonjakan trafik ekstrem atau serangan DoS.
 * 
 * 5. DIAGNOSTICS, LOGGING & ADVISORY SYSTEM (halmos_log & halmos_core_config):
 *    - Menyediakan laporan audit kapasitas sistem saat pertama kali menyala (halmos -p).
 *    - Memberikan saran taktis (advisory) bagi administrator apabila batas kernel sistem 
 *      seperti ulimit atau konfigurasi pool backend kurang optimal untuk perangkat keras.
 * 
 * TANGGUNG JAWAB BERKAS (MAIN.C):
 * Program main.c ini bertindak sebagai pusat kendali utama (entry point) yang menginisialisasi 
 * argumen terminal, memuat konfigurasi global, mengeksekusi mesin adaptif, memvalidasi 
 * alokasi pool backend lintas runtime, dan menjalankan siklus utama server (main event loop).
 * ========================================================================== */

#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_conn_table.h"
#include "halmos_core_event_loop.h"
#include "halmos_core_queue.h"
#include "halmos_core_thread_pool.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"
#include "halmos_fcgi_upstream.h"
#include "halmos_fcgi_event_loop.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_thread_pool.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_ws_system.h"
#include "halmos_log.h"

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>

#include <string.h>
#include <unistd.h>

// Definisi Identitas & Konfigurasi Global
#define HALMOS_NAME       "Halmos Web Server"
#define HALMOS_VERSION    "1.1.2-RC1"
#define HALMOS_CONFIG_PATH "/etc/halmos/halmos.conf"

// Deklarasi variabel global pengendali loop (sesuai modul event loop Anda)
extern volatile sig_atomic_t server_running;
extern int shutdown_pipe[2]; // Jika menggunakan Self-Pipe Trick

// 1. Signal handler yang benar-benar Async-Signal-Safe
static void handle_shutdown_signal(int sig) {
    (void)sig;
    server_running = 0;
    
    // Jika menggunakan Self-Pipe Trick untuk membangunkan epoll_wait seketika:
    char buf = 1;
    ssize_t w = write(shutdown_pipe[1], &buf, 1);
    (void)w;
}

void setup_signals(void) {
    struct sigaction sa;
    sa.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Tanpa SA_RESTART agar epoll_wait bisa terinterupsi/terbangun

    signal(SIGPIPE, SIG_IGN);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}


// Fungsi untuk mencetak footprint memori/RAM (VmRSS / VmHWM)
void log_memory_footprint(const char *label, const char *target_key) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;

    char line[128];
    long mem_kb = 0;
    size_t key_len = strlen(target_key);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, target_key, key_len) == 0) {
            mem_kb = atol(line + key_len); // Ambil nilai dalam Kilobytes
            break;
        }
    }
    fclose(fp);

    if (mem_kb > 0) {
        double mem_mb = (double)mem_kb / 1024.0;
        write_log("[CORE] %s: %.2f MB", label, mem_mb);
    }
}

int main(int argc, char *argv[]) {
    // 0. Tangani Argumen CLI (Version, Help, Test Config)
    if (argc > 1) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("%s v%s\n", HALMOS_NAME, HALMOS_VERSION);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("%s v%s\n", HALMOS_NAME, HALMOS_VERSION);
            printf("Usage:\n  halmos [option]\n\n");
            printf("Options:\n");
            printf("  -p, --profile    Analyze hardware resources and exit\n");
            printf("  -t, --test       Test configuration file syntax and exit\n");
            printf("  -v, --version    Output version information and exit\n");
            printf("Configuration:\n");
            printf("  Config file is loaded from: %s\n", HALMOS_CONFIG_PATH);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-p") == 0 || strcmp(argv[1], "--profile") == 0) {
            if (core_config_load(HALMOS_CONFIG_PATH) != 0) {
                fprintf(stderr, "[ERROR] Configuration test FAILED: Cannot parse %s\n", HALMOS_CONFIG_PATH);
                return EXIT_FAILURE;
            }
            if (config.php_fpm_config_path[0] != '\0') {
                if (access(config.php_fpm_config_path, R_OK) != 0) {
                    fprintf(stderr, "[WARN] PHP-FPM config path NOT FOUND or unreadable: %s\n", config.php_fpm_config_path);
                    fprintf(stderr, "       Hint: Check if PHP-FPM is installed or if the path/permissions are correct.\n");
                }
            } else {
                printf("[WARN] php_fpm_config_path is empty in configuration.\n");
            }
            core_adaptive_init(1);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--test") == 0) {
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
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("%s v%s\n", HALMOS_NAME, HALMOS_VERSION);
            return EXIT_SUCCESS;
        } else {
            printf("Unknown command. Use '-h' or '--help' for available options.\n");
            return EXIT_SUCCESS;
        }
    }

    setup_signals();

    // 1. Load Konfigurasi (Log ke stderr jika gagal sebelum logger aktif)
    if(core_config_load(HALMOS_CONFIG_PATH) != 0){
        return EXIT_FAILURE;
    }

    // 2. Aktifkan thread untuk penulisan log
    start_thread_logger();
    write_log("[CORE] Initializing %s v%s...", HALMOS_NAME, HALMOS_VERSION);

    // 3. Hitung Parameter Hardware & OS Limit
    core_adaptive_init(0);

    // 4. Inisialisasi connection table
    if (core_conn_t_init() != 0) {
        fprintf(stderr, "[FATAL] Failed to allocate core connection tracking table.\n");
        return EXIT_FAILURE;
    }

    // 5. Inisialisasi Layanan SSL
    if (config.tls_enabled) {
        if(ssl_init() != 0) {
            fprintf(stderr, "[FATAL] Failed to initialize SSL Engine.\n");
            stop_thread_logger();
            return EXIT_FAILURE;
        }
        // Mapping FD ke SSL (Ukuran g_core_queue_capacity + buffer aman)
        ssl_init_mapping(g_core_queue_capacity + 2000); 
        write_log("[CORE] TLS Engine & Mapping ready.");
    }
    
    // 6. Inisialisasi Virtual Host
    http_vhost_init_all();

    // 7. Inisialisasi Registry & Hash Table WebSocket
    halmos_ws_system_init();
    write_log("[CORE] WebSocket Registry & Subsystems ready.");

    // 8. Inisialisasi Antrean (Dapur) & Thread Pool Dinamis
    // Menggunakan batas antrean dari config
    core_queue_thread_worker_start();
    write_log("[CORE] Core Worker thread pool started dynamically.");

    // 9. Inisialisasi janitor jika fungsi rate limited diaktifkan
    if(config.rate_limit_enabled == true) {
        sec_traffic_start_janitor();
        write_log("[SEC] Security Janitor thread started.");    
    }
    
    // 10. Start upstream untuk koneksi ke backend
    if (!fcgi_upstream_start()) {
        fprintf(stderr, "Failed to create upstream backend or connect to backend socket!\n");
        exit(EXIT_FAILURE);
    }
    write_log("[UPSTREAM] FastCGI Upstream Connection Pool initialized.");

    // 11. Inisialisasi session pool untuk sesi di backend
    if (!fcgi_global_pool_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize FastCGI Global Session Pool!\n");
        exit(EXIT_FAILURE);
    }
    write_log("[CORE] FastCGI Global Session Pool initialized.");

    // 12. Inisialisasi queue backend, untuk menampung antrian request ke backend
    if (!fcgi_queue_start()) {
        fprintf(stderr, "Failed to initialize FCGI task queue!\n");
        exit(EXIT_FAILURE);
    }
    write_log("[CORE] FastCGI Task Queue started.");

    // 13. Inisialisasi event loop di backend
    if (!fcgi_event_loop_start()) {
        fprintf(stderr, "Failed to initialize FastCGI Async Event Loop!\n> exit(1);\n");
        return 1;
    }
    write_log("[CORE] FastCGI Async Event Loop started.");

    // 14. Inisialisasi Worker Pool FastCGI
    if (!fcgi_thread_pool_start()) {
        fprintf(stderr, "Failed to initialize FCGI thread pool!\n");
        return 1;
    }
    write_log("[CORE] FastCGI Worker Pool started.");
    
    // 15. Inisialisasi Network & Epoll di core
    if (core_event_loop_start() != 0) {
        fprintf(stderr, "[FATAL] Failed to start event loop.\n");
        stop_thread_logger();
        return EXIT_FAILURE;
    }
    write_log("[CORE] Core Network & Epoll Event Loop started.");

    // 16. Inisialisasi virtual host inotify
    // === TAMBAHKAN INI DI SINI ===
    // Karena epoll_fd sudah tercipta di dalam core_event_loop_start(), 
    // kita bisa langsung mendaftarkan inotify vhost ke epoll utama.
    // (Asumsikan epoll_fd bisa diakses secara global atau diekspos via getter)
    extern int epoll_fd; // Jika epoll_fd dideklarasikan global di core event loop
    http_vhost_init_inotify(epoll_fd);
    write_log("[CORE] Virtual Host Inotify watcher registered to epoll.");
    
    write_log("[CORE] Starting Halmos Web Server v1.0.0-rc1...");
    log_memory_footprint("Initial Memory Footprint (VmRSS)", "VmRSS:");
   
    // 17. RUN! Resepsionis Epoll Utama
    core_event_loop_run();

    // =======================================================
    // --- GRACEFUL SHUTDOWN CLEANUP SEQUENCE ---
    // =======================================================
    
    log_memory_footprint("Peak Memory Footprint (VmHWM)", "VmHWM:");

    core_event_loop_stop();
    write_log("[CORE] Shutdown signal caught. Cleaning up resources...");

    // Hancurkan Global Session Pool di awal shutdown ===
    fcgi_global_pool_destroy();
    write_log("[CORE] FastCGI Global Session Pool destroyed.");
    
    fcgi_queue_stop();
    write_log("[CORE] FastCGI Queue cleaned up.");

    // 1. Hentikan FastCGI Worker Pool TERLEBIH DAHULU (Bangunkan thread yang menunggu di queue)
    fcgi_event_loop_stop();
    write_log("[CORE] FastCGI Event Loop cleaned up.");

    // 2. Hentikan worker yang memproses task, pastikan thread-nya sudah join/mati total
    fcgi_thread_pool_stop();
    write_log("[CORE] FastCGI Worker Pool stopped.");

    fcgi_upstream_stop();
    write_log("[CORE] FastCGI Upstream Connection Pool destroyed.");

    // 3. Stop Worker Thread Pool utama Halmos & Join semua thread
    core_queue_thread_worker_stop();
    write_log("[CORE] Core Worker thread pool joined & stopped.");

    // 4. Stop Janitor Security Thread
    if (config.rate_limit_enabled) {
        sec_traffic_stop_janitor();
    }
    
    // 5. Bersihkan WebSocket & TLS
    ws_system_destroy();
    write_log("[CORE] WebSocket Registry & Subsystems destroyed.");
    
    if (config.tls_enabled) {
        ssl_cleanup();
        write_log("[CORE] TLS Resources cleaned up.");
    }
   
    // 6. DESTROY CORE CONNECTION TABLE
    core_conn_t_destroy();
    write_log("[CORE] Connection Table destroyed.");

    write_log("[CORE] %s shutdown complete. Bye!", HALMOS_NAME);
    // 7. TERAKHIR: Wajib tempatkan stop_thread_logger() di paling ujung!
    stop_thread_logger();
    
    return EXIT_SUCCESS;
}