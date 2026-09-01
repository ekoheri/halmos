#include "halmos_core_adaptive.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
#include "halmos_fcgi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>

// Macro konstan untuk arsitektur adaptive
#define MAX_EVENT_BATCH_SIZE 1024
#define DEFAULT_REQUEST_BUFFER_SIZE 4096

// Definisi variabel global
int g_event_batch_size = 0;
int g_fcgi_pool_size = 0;
int g_worker_max = 0;
int g_worker_min = 0;
int g_queue_capacity = 0;

typedef struct {
    int max_children;
    int backlog;
    char mode[16]; 
} PHPConfig;

PHPConfig fetch_php_fpm_config(void) {
    // Fallback baseline konservatif jika parsing gagal
    PHPConfig cfg = {50, 511, "dynamic"}; 

    if (strlen(config.php_fpm_config_path) == 0) {
        write_log_error("[WARN] PHP-FPM config path not defined, using baseline default (max_children=50)");
        return cfg;
    }

    FILE *fp = fopen(config.php_fpm_config_path, "r");
    if (!fp) {
        write_log_error("[ERR] Failed to open PHP-FPM config: %s. Fallback to max_children=50", config.php_fpm_config_path);
        return cfg;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *ptr = line;
        while (*ptr == ' ' || *ptr == '\t') ptr++;

        if (*ptr == ';' || *ptr == '#' || *ptr == '\n' || *ptr == '\0') continue;

        if (strstr(ptr, "pm.max_children")) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                char *endptr;
                errno = 0;
                long val = strtol(eq + 1, &endptr, 10);
                
                // Robust Parsing: Pastikan ada angka valid dan berharga positif
                if (errno == 0 && endptr != (eq + 1) && val > 0) {
                    cfg.max_children = (int)val;
                } else {
                    write_log_error("[WARN] Invalid pm.max_children format in PHP config. Fallback to default (%d)", cfg.max_children);
                }
            }
        }
        else if (strstr(ptr, "listen.backlog")) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                char *endptr;
                errno = 0;
                long val = strtol(eq + 1, &endptr, 10);
                if (errno == 0 && endptr != (eq + 1) && val > 0) {
                    cfg.backlog = (int)val;
                }
            }
        }
        else if (strstr(ptr, "pm =") || strstr(ptr, "pm=")) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                char *val = eq + 1;
                while (*val == ' ' || *val == '\t') val++;
                // Boundary check %15s untuk keamanan buffer
                sscanf(val, "%15s", cfg.mode); 
            }
        }
    }
    fclose(fp);
    return cfg;
}

void core_adaptive_init(void) {
    // 1. Deteksi Hardware Baseline dengan Defense Error Handling
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    struct rlimit rl;
    struct sysinfo si;

    // Pengecekan return value getrlimit
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        write_log_error("[ERR] Failed to retrieve RLIMIT_NOFILE, setting fallback rlim_cur=4096");
        rl.rlim_cur = 4096;
    }

    // Pengecekan return value sysinfo
    if (sysinfo(&si) != 0) {
        write_log_error("[ERR] Failed to retrieve system memory info via sysinfo()");
        memset(&si, 0, sizeof(si));
    }

    /*
     * Conservative CPU-based worker heuristic.
     * The 64x multiplier intentionally limits concurrency
     * to avoid excessive context switching and memory pressure.
     */
    int cpu_based_max = (int)(num_cores * 64); 

    /*
     * Memory-based worker heuristic using integer arithmetic (uint64_t).
     * Allocates a conservative 10% memory budget to connection buffers
     * while preventing 32-bit/64-bit platform overflow.
     */
    uint64_t buf_size = (config.request_buffer_size > 0) ? (uint64_t)config.request_buffer_size : DEFAULT_REQUEST_BUFFER_SIZE;
    uint64_t total_ram_bytes = (uint64_t)si.totalram * (uint64_t)si.mem_unit;
    
    int ram_based_max = 0;
    if (total_ram_bytes > 0 && buf_size > 0) {
        ram_based_max = (int)((total_ram_bytes / buf_size) / 10);
    } else {
        ram_based_max = cpu_based_max; // Fallback jika sysinfo gagal
    }

    int recommended_val = (cpu_based_max < ram_based_max) ? cpu_based_max : ram_based_max;
    
    // Baseline Worker Ceiling: 1024
    if (recommended_val > 1024) recommended_val = 1024;
    if (recommended_val < 32)   recommended_val = 32;

    g_worker_max = recommended_val;
    g_worker_min = (int)num_cores * 4;
    if (g_worker_min > g_worker_max) g_worker_min = g_worker_max;

    // 2. Ambil Konfigurasi PHP-FPM
    PHPConfig php = fetch_php_fpm_config();
    
    // 3. Pembagian Quota FCGI Presisi (Pure Integer Arithmetic)
    fcgi_pool.php_quota = php.max_children; 
    
    int sisa_jatah = g_worker_max - fcgi_pool.php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0;
    }

    // Alokasi presisi tanpa floating point
    fcgi_pool.rust_quota   = (sisa_jatah * 2) / 5; 
    fcgi_pool.python_quota = sisa_jatah - fcgi_pool.rust_quota; 
    
    fcgi_pool.pool_size = fcgi_pool.php_quota + fcgi_pool.rust_quota + fcgi_pool.python_quota;
    g_fcgi_pool_size    = fcgi_pool.pool_size;

    // 4. Batch Size & Queue Capacity dengan tipe rlim_t Native
    g_event_batch_size = (g_worker_max > MAX_EVENT_BATCH_SIZE) ? MAX_EVENT_BATCH_SIZE : g_worker_max;

    rlim_t smart_ulimit = (rlim_t)g_worker_max + 2000; 

    if (rl.rlim_cur > (rlim_t)g_worker_max) {
        g_queue_capacity = (int)((rl.rlim_cur - (rlim_t)g_worker_max) / 2);
    } else {
        g_queue_capacity = 2000;
    }
    if (g_queue_capacity < 2000) g_queue_capacity = 2000;

    // 5. Logging & Audit System
    write_log("[CORE] Adaptive engine initialized (Ceiling: 1024 Workers)");
    write_log("[CORE] Workers (Min/Max): %d/%d | Event Batch: %d | Queue Capacity: %d", 
              g_worker_min, g_worker_max, g_event_batch_size, g_queue_capacity);
    write_log("[FCGI] Quotas -> PHP: %d | Rust: %d | Python: %d | Total Pool: %d", 
              fcgi_pool.php_quota, fcgi_pool.rust_quota, fcgi_pool.python_quota, g_fcgi_pool_size);

    // Audit System ulimit
    if (rl.rlim_cur < smart_ulimit) {
        write_log("[ADVICE] System ulimit (%lu) is low for high load", (unsigned long)rl.rlim_cur);
        write_log("[ADVICE] Action: Run 'ulimit -n %lu' for optimal FD headroom", (unsigned long)smart_ulimit);
    }

    // Audit PHP-FPM Configuration
    if (php.max_children > g_worker_max) {
        write_log_error("[CRITICAL] PHP-FPM max_children (%d) exceeds server worker capacity (%d)!", 
                        php.max_children, g_worker_max);
        write_log("[ADVICE] Action: Decrease PHP-FPM max_children to %d to prevent CPU starvation", g_worker_max);
    } 
    else if (php.max_children < (g_worker_max / 2)) {
        write_log("[ADVICE] PHP-FPM max_children (%d) is under-utilized for this hardware", php.max_children);
        write_log("[ADVICE] Action: Consider increasing PHP-FPM max_children up to %d", g_worker_max / 2);
    }
}