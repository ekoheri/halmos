#include "halmos_core_adaptive.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
#include "halmos_fcgi_pool.h"

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

void core_adaptive_init(int print_to_terminal) {
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
        calculated_max_fd = 65536; 
    } else if (rl.rlim_cur > UINT32_MAX) {
        calculated_max_fd = UINT32_MAX; 
    } else {
        calculated_max_fd = (uint32_t)rl.rlim_cur;
    }

    // Koreksi Poin 5: Jangan menaikkan batas FD secara artifisial ke 1024 jika OS membatasi lebih kecil.
    // Cukup pastikan nilainya tidak 0/negatif (batas aman minimal misal 64), lalu biarkan g_max_fd jujur apa adanya.
    if (calculated_max_fd < 64) calculated_max_fd = 64;
    g_max_fd = calculated_max_fd;

    // Total RAM dalam MB
    unsigned long total_ram_mb = (unsigned long)((si.totalram * si.mem_unit) / (1024 * 1024));
    if (total_ram_mb == 0) total_ram_mb = 1024; // Fallback pengaman jika sysinfo gagal

    // 2. Ambil Memory Budget dari konfigurasi (dengan nilai default aman jika belum diatur)
    int php_mem_budget    = (config.php.memory_budget > 0) ? config.php.memory_budget : 20;     
    int python_mem_budget = (config.python.memory_budget > 0) ? config.python.memory_budget : 40; 
    int rust_mem_budget   = (config.rust.memory_budget > 0) ? config.rust.memory_budget : 15;   

    // Deteksi backend mana saja yang aktif berdasarkan konfigurasi node/ekstensi/path
    bool is_php_active    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python_active = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust_active   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    int active_backend_count = (is_php_active ? 1 : 0) + (is_python_active ? 1 : 0) + (is_rust_active ? 1 : 0);
    if (active_backend_count == 0) active_backend_count = 1;

    // 3. Alokasi RAM Aman untuk OS & Database (Cadangan 25%, minimal 1GB, maksimal 4GB)
    unsigned long reserved_ram_mb = total_ram_mb / 4;
    if (reserved_ram_mb < 1024) reserved_ram_mb = 1024;
    if (reserved_ram_mb > 4096) reserved_ram_mb = 4096;

    unsigned long available_for_web = total_ram_mb - reserved_ram_mb;

    // 4. Hitung Anggaran RAM Berdasarkan Kombinasi Backend yang Aktif
    unsigned long php_budget_ram    = 0;
    unsigned long python_budget_ram = 0;
    unsigned long rust_budget_ram   = 0;

    if (active_backend_count == 3) {
        php_budget_ram    = (available_for_web * 50) / 100;
        python_budget_ram = (available_for_web * 30) / 100;
        rust_budget_ram   = (available_for_web * 20) / 100;
    } else if (active_backend_count == 2) {
        if (is_php_active && is_python_active) {
            php_budget_ram    = (available_for_web * 60) / 100;
            python_budget_ram = (available_for_web * 40) / 100;
        } else if (is_php_active && is_rust_active) {
            php_budget_ram    = (available_for_web * 70) / 100;
            rust_budget_ram   = (available_for_web * 30) / 100;
        } else if (is_python_active && is_rust_active) {
            python_budget_ram = (available_for_web * 60) / 100;
            rust_budget_ram   = (available_for_web * 40) / 100;
        }
    } else {
        if (is_php_active)    php_budget_ram    = available_for_web;
        if (is_python_active) python_budget_ram = available_for_web;
        if (is_rust_active)   rust_budget_ram   = available_for_web;
    }

    int max_php_by_ram    = is_php_active ? (int)(php_budget_ram / php_mem_budget) : 0;
    int max_python_by_ram = is_python_active ? (int)(python_budget_ram / python_mem_budget) : 0;
    int max_rust_by_ram   = is_rust_active ? (int)(rust_budget_ram / rust_mem_budget) : 0;

    // Hardware-aware recommended worker ceiling (dikomparasi dengan batas kapasitas RAM)
    int cpu_based_max = (int)(num_cores * 64); 
    int ram_total_max = max_php_by_ram + max_python_by_ram + max_rust_by_ram;
    if (ram_total_max < 32 && active_backend_count > 0) ram_total_max = 32;

    int recommended_val = (cpu_based_max < ram_total_max) ? cpu_based_max : ram_total_max;
    
    if (recommended_val > 1024) recommended_val = 1024;
    if (recommended_val < 32)   recommended_val = 32;

    g_worker_max = recommended_val;
    g_worker_min = (int)num_cores * 4;
    if (g_worker_min > g_worker_max) g_worker_min = g_worker_max;

    // 5. Fetch Administrator's PHP-FPM Configuration
    PHPConfig php = fetch_php_fpm_config();
    
    // 6. FCGI Quota Mapping Dinamis Berdasarkan Aktif/Tidaknya Backend
    fcgi_pool.php_quota = is_php_active ? php.max_children : 0; 
    
    int sisa_jatah = g_worker_max - fcgi_pool.php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0; 
    }

    if (is_python_active && is_rust_active) {
        unsigned long total_py_rust_ram = python_budget_ram + rust_budget_ram;
        if (total_py_rust_ram > 0) {
            fcgi_pool.python_quota = (sisa_jatah * python_budget_ram) / total_py_rust_ram;
            fcgi_pool.rust_quota   = sisa_jatah - fcgi_pool.python_quota;
        } else {
            fcgi_pool.python_quota = sisa_jatah / 2;
            fcgi_pool.rust_quota   = sisa_jatah - fcgi_pool.python_quota;
        }
    } else if (is_python_active) {
        fcgi_pool.python_quota = sisa_jatah;
        fcgi_pool.rust_quota   = 0;
    } else if (is_rust_active) {
        fcgi_pool.rust_quota   = sisa_jatah;
        fcgi_pool.python_quota = 0;
    } else {
        fcgi_pool.python_quota = 0;
        fcgi_pool.rust_quota   = 0;
    }

    fcgi_pool.pool_size    = fcgi_pool.php_quota + fcgi_pool.rust_quota + fcgi_pool.python_quota;
    g_fcgi_pool_size       = fcgi_pool.pool_size;

    // 7. Queue Capacity Berbasis g_max_fd aktual
    g_event_batch_size = (g_worker_max > MAX_EVENT_BATCH_SIZE) ? MAX_EVENT_BATCH_SIZE : g_worker_max;

    if (g_max_fd > (uint32_t)g_worker_max) {
        uint32_t sisa_fd = g_max_fd - (uint32_t)g_worker_max;
        g_queue_capacity = (int)((sisa_fd * 60U) / 100U);
    } else {
        g_queue_capacity = 256; 
    }

    if (g_queue_capacity > MAX_QUEUE_CAPACITY) {
        g_queue_capacity = MAX_QUEUE_CAPACITY;
    }

    if (g_queue_capacity < 256) {
        g_queue_capacity = 256;
    }

    // 8. Logging & Advisory System
    char log_buf_1[256] = "";
    char log_buf_2[256] = "";
    char log_buf_3[256] = "";
    char log_buf_mem[256] = "";
    
    snprintf(log_buf_1, sizeof(log_buf_1),"[CORE] Hardware-Aware Init -> Cores: %ld | RAM: %lu MB | Max File Descriptor (FD): %u", 
              num_cores, total_ram_mb, g_max_fd);

    snprintf(log_buf_2, sizeof(log_buf_2),"[CORE] Workers (Min/Recommended Ceiling): %d/%d | Event Batch: %d | Queue Capacity: %d", 
              g_worker_min, g_worker_max, g_event_batch_size, g_queue_capacity);
    
    snprintf(log_buf_3, sizeof(log_buf_3),"[FCGI] Workers Allocation -> PHP: %d (from max_children configuration) | Rust: %d | Python: %d | Total Workers: %d", 
              fcgi_pool.php_quota, fcgi_pool.rust_quota, fcgi_pool.python_quota, g_fcgi_pool_size);          

    snprintf(log_buf_mem, sizeof(log_buf_mem), "[MEM] Budget Awareness -> Reserved (OS/DB): %lu MB | Estimation per Process [PHP: %dMB, Python: %dMB, Rust: %dMB]", 
              reserved_ram_mb, php_mem_budget, python_mem_budget, rust_mem_budget);
    
    // Koreksi Poin 2 & 4: Advisory ulimit yang bersih, tidak kaku, dan informatif
    char log_buf_4[256] = "";
    char log_buf_5[256] = "";

    rlim_t min_safe_ulimit = 4096;
    if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < min_safe_ulimit) {
        snprintf(log_buf_4, sizeof(log_buf_4),"[WARN] System Max FD/ulimit = %lu is relatively low for high-concurrency workloads (recommended baseline: %lu)",
                  (unsigned long)rl.rlim_cur, (unsigned long)min_safe_ulimit);          
    
        snprintf(log_buf_5, sizeof(log_buf_5),"[ADVICE] Consider increasing ulimit (e.g. run 'ulimit -n 4096' or configure limits.conf) according to expected concurrency");           
    }

    // Berikan juga warning jika g_max_fd yang dibaca aktual terlalu rendah
    char log_buf_6[256] = "";
    if (g_max_fd < 1024) {
        snprintf(log_buf_6, sizeof(log_buf_6),"[WARN] System System Max FD (ulimit) (%u) is low for a high-concurrency server", g_max_fd); 
    }

    // Audit PHP-FPM Configuration
    char log_buf_7[256] = "";
    char log_buf_8[1024] = "";
    char log_buf_9[256] = "";
    char log_buf_10[1024] = "";
    char log_buf_11[256] = "";
    if (php.max_children > g_worker_max) {
        snprintf(log_buf_7, sizeof(log_buf_7),"[WARN] PHP-FPM max_children (%d) exceeds hardware-aware worker baseline (%d)", 
                  php.max_children, g_worker_max); 
        snprintf(log_buf_8, sizeof(log_buf_8),"[ADVICE] Action: Review PHP-FPM max_children in '%s' if resource contention occurs", 
                  config.php_fpm_config_path);          
    } 
    else if (php.max_children < (g_worker_max / 4)) {
        int suggested_max = g_worker_max / 2;
        int suggested_start = suggested_max / 4;
        int suggested_min = suggested_start;
        int suggested_max_spare = suggested_max / 2;

        snprintf(log_buf_9, sizeof(log_buf_9),"[ADVICE] PHP-FPM max_children (%d) is conservative for detected hardware", 
                    php.max_children);
        snprintf(log_buf_10, sizeof(log_buf_10),"[ADVICE] Action: Consider scaling pool in '%s' up to max_children = %d based on PHP workload", 
                  config.php_fpm_config_path, suggested_max);  
        snprintf(log_buf_11, sizeof(log_buf_11),"[ADVICE] Supporting Config Tip -> Adjust pm.start_servers = %d, min_spare = %d, max_spare = %d accordingly", 
                  suggested_start, suggested_min, suggested_max_spare);                     
    }

    if(print_to_terminal == 0) {
        if (log_buf_1[0] != '\0')     write_log("%s", log_buf_1);
        if (log_buf_2[0] != '\0')     write_log("%s", log_buf_2);
        if (log_buf_3[0] != '\0')     write_log("%s", log_buf_3);
        if (log_buf_mem[0] != '\0')   write_log("%s", log_buf_mem);
        if (log_buf_4[0] != '\0')     write_log("%s", log_buf_4);
        if (log_buf_5[0] != '\0')     write_log("%s", log_buf_5);
        if (log_buf_6[0] != '\0')     write_log("%s", log_buf_6);
        if (log_buf_7[0] != '\0')     write_log("%s", log_buf_7);
        if (log_buf_8[0] != '\0')     write_log("%s", log_buf_8);
        if (log_buf_9[0] != '\0')     write_log("%s", log_buf_9);
        if (log_buf_10[0] != '\0')    write_log("%s", log_buf_10);
        if (log_buf_11[0] != '\0')    write_log("%s", log_buf_11);
    } else {
        printf("\n--- HALMOS ADAPTIVE CAPACITY REPORT ---\n");
        if (log_buf_1[0] != '\0')     printf("%s\n", log_buf_1);
        if (log_buf_2[0] != '\0')     printf("%s\n", log_buf_2);
        if (log_buf_3[0] != '\0')     printf("%s\n", log_buf_3);
        if (log_buf_mem[0] != '\0')   printf("%s\n", log_buf_mem);
        if (log_buf_4[0] != '\0')     printf("%s\n", log_buf_4);
        if (log_buf_5[0] != '\0')     printf("%s\n", log_buf_5);
        if (log_buf_6[0] != '\0')     printf("%s\n", log_buf_6);
        if (log_buf_7[0] != '\0')     printf("%s\n", log_buf_7);
        if (log_buf_8[0] != '\0')     printf("%s\n", log_buf_8);
        if (log_buf_9[0] != '\0')     printf("%s\n", log_buf_9);
        if (log_buf_10[0] != '\0')    printf("%s\n", log_buf_10);
        if (log_buf_11[0] != '\0')    printf("%s\n", log_buf_11);
        printf("---------------------------------------\n");
    }
}

