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

#define MAX_EVENT_BATCH_SIZE 1024
#define MAX_QUEUE_CAPACITY 4096

uint32_t g_max_fd = 0;
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

        // 1. Bersihkan newline / carriage return di akhir baris (mendukung format Linux & Windows CRLF)
        line[strcspn(line, "\r\n")] = '\0';

        // 2. Buang komentar inline (simbol ';' atau '#') dengan mengubahnya menjadi string terminator ('\0')
        char *comment = strchr(ptr, ';');
        if (!comment) comment = strchr(ptr, '#');
        if (comment) *comment = '\0';

        // 3. Lewati spasi atau tab di awal baris
        while (*ptr == ' ' || *ptr == '\t') ptr++;

        // 4. Lewati baris kosong atau baris komentar penuh
        if (*ptr == '\0') continue;

        // 5. Parse konfigurasi dengan aman
        if (strstr(ptr, "pm.max_children")) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                char *endptr;
                errno = 0;
                long val = strtol(eq + 1, &endptr, 10);
                if (errno == 0 && endptr != (eq + 1) && val > 0) {
                    cfg.max_children = (int)val;
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
        else if (strstr(ptr, "pm") && (strstr(ptr, "pm =") || strstr(ptr, "pm="))) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                // Pastikan key persis "pm" (tidak ada titik '.' sebelum tanda '=' seperti pm.max_children)
                int has_dot = 0;
                for (char *p = ptr; p < eq; p++) {
                    if (*p == '.') { has_dot = 1; break; }
                }
                if (!has_dot) {
                    char *val = eq + 1;
                    while (*val == ' ' || *val == '\t') val++;
                    if (sscanf(val, "%15s", cfg.mode) == 1) {
                        // Mode berhasil diekstrak dengan aman tanpa gangguan komentar/spasi
                    }
                }
            }
        }
    }
    fclose(fp);
    return cfg;
}

void core_adaptive_init(void) {
    // 1. Hardware Awareness Baseline Detection
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    struct rlimit rl;
    struct sysinfo si;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        rl.rlim_cur = 4096;
    }
    if (sysinfo(&si) != 0) {
        memset(&si, 0, sizeof(si));
    }

    uint32_t calculated_max_fd;
    
    // Periksa apakah nilainya unlimited
    if (rl.rlim_cur == RLIM_INFINITY) {
        // Berikan batas aman rasional untuk server (misal: 65536 atau baca dari konstanta sysctl)
        calculated_max_fd = 65536; 
    } else if (rl.rlim_cur > UINT32_MAX) {
        calculated_max_fd = UINT32_MAX; // Mencegah overflow casting
    } else {
        calculated_max_fd = (uint32_t)rl.rlim_cur;
    }

    if (calculated_max_fd < 1024) calculated_max_fd = 1024;
    g_max_fd = calculated_max_fd;

    /*
     * Hardware-aware recommended worker ceiling.
     * This value is an initialization baseline, not a runtime
     * auto-scaling decision and not an administrator override.
     */
    int cpu_based_max = (int)(num_cores * 64); 
    int recommended_val = cpu_based_max;
    
    if (recommended_val > 1024) recommended_val = 1024;
    if (recommended_val < 32)   recommended_val = 32;

    g_worker_max = recommended_val;
    g_worker_min = (int)num_cores * 4;
    if (g_worker_min > g_worker_max) g_worker_min = g_worker_max;

    // 2. Fetch Administrator's PHP-FPM Configuration
    PHPConfig php = fetch_php_fpm_config();
    
    // 3. FCGI Quota Mapping (Murni mencerminkan konfigurasi administrator)
    fcgi_pool.php_quota = php.max_children; 
    
    int sisa_jatah = g_worker_max - fcgi_pool.php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0; 
    }

    fcgi_pool.rust_quota   = (sisa_jatah * 2) / 5; 
    fcgi_pool.python_quota = sisa_jatah - fcgi_pool.rust_quota; 
    fcgi_pool.pool_size    = fcgi_pool.php_quota + fcgi_pool.rust_quota + fcgi_pool.python_quota;
    g_fcgi_pool_size       = fcgi_pool.pool_size;

    // 4. Queue Capacity Berbasis g_max_fd yang sudah ternormalisasi (Aman dari RLIM_INFINITY)
    g_event_batch_size = (g_worker_max > MAX_EVENT_BATCH_SIZE) ? MAX_EVENT_BATCH_SIZE : g_worker_max;

    if (g_max_fd > (uint32_t)g_worker_max) {
        uint32_t sisa_fd = g_max_fd - (uint32_t)g_worker_max;
        g_queue_capacity = (int)((sisa_fd * 60U) / 100U);
    } else {
        g_queue_capacity = 256; 
    }

    // Batasi queue dengan upper bound agar tidak membengkak berlebihan (Resource-Aware Boundary)
    if (g_queue_capacity > MAX_QUEUE_CAPACITY) {
        g_queue_capacity = MAX_QUEUE_CAPACITY;
    }

    if (g_queue_capacity < 256) {
        g_queue_capacity = 256;
    }

    // 5. Logging & Advisory System (Decision Support untuk Administrator)
    write_log("[CORE] Hardware-Aware Init -> Cores: %ld | RAM: %lu MB | Max FD: %u", 
              num_cores, (unsigned long)((si.totalram * si.mem_unit) / (1024 * 1024)), g_max_fd);
    write_log("[CORE] Workers (Min/Recommended Ceiling): %d/%d | Event Batch: %d | Queue Capacity: %d", 
              g_worker_min, g_worker_max, g_event_batch_size, g_queue_capacity);
    write_log("[FCGI] Quotas -> PHP: %d | Rust: %d | Python: %d | Total Pool: %d", 
              fcgi_pool.php_quota, fcgi_pool.rust_quota, fcgi_pool.python_quota, g_fcgi_pool_size);

    // Audit System ulimit
    rlim_t ideal_ulimit = (rlim_t)(g_worker_max + g_queue_capacity + 500);
    if (rl.rlim_cur < ideal_ulimit) {
        write_log("[WARN] System ulimit (%lu) is lower than recommended headroom (%lu)", 
                  (unsigned long)rl.rlim_cur, (unsigned long)ideal_ulimit);
        write_log("[ADVICE] Action: Run 'ulimit -n %lu' for optimal FD headroom", (unsigned long)ideal_ulimit);
    }

    // Audit PHP-FPM Configuration (Advisory murni, menghormati kebijakan administrator)
    if (php.max_children > g_worker_max) {
        write_log("[WARN] PHP-FPM max_children (%d) exceeds hardware-aware worker baseline (%d)", 
                  php.max_children, g_worker_max);
        write_log("[ADVICE] Action: Review PHP-FPM max_children in '%s' if resource contention occurs", 
                  config.php_fpm_config_path);
    } 
    else if (php.max_children < (g_worker_max / 4)) {
        int suggested_max = g_worker_max / 2;
        int suggested_start = suggested_max / 4;
        int suggested_min = suggested_start;
        int suggested_max_spare = suggested_max / 2;

        write_log("[ADVICE] PHP-FPM max_children (%d) is conservative for detected hardware", php.max_children);
        write_log("[ADVICE] Action: Consider scaling pool in '%s' up to max_children = %d based on PHP workload", 
                  config.php_fpm_config_path, suggested_max);
        write_log("[ADVICE] Supporting Config Tip -> Adjust pm.start_servers = %d, min_spare = %d, max_spare = %d accordingly", 
                  suggested_start, suggested_min, suggested_max_spare);
    }
}