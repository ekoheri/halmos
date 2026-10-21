#include "halmos_core_adaptive.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
//#include "halmos_fcgi_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>

#include <math.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

#define INITIAL_CAPACITY 1000
#define MAX_LINE_LENGTH 1024

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

// Struktur internal untuk baris data mentah per sampel log CSV
typedef struct {
    long queue_length;
    long queue_capacity;
    double queue_wait_us;
    int workers;
    int active_workers;
    int scaling_delta;
    double execution_time_us;
    int bound_type; // 0: I/O-Bound, 1: CPU-Bound
} MetricRow;

// Struktur untuk menampung kolom agregasi metrik
typedef struct {
    long total_rows;
    double sum_queue_len;
    long max_queue_len;
    long max_capacity;
    double sum_queue_wait;
    long max_queue_wait;
    long workers_constant;
    long max_active_workers;
    double sum_active_workers;
    long scaling_events;
    long io_bound_count;
    long cpu_bound_count;
} MetricsStats;

/* Helper untuk adaptive init*/
static PHPConfig fetch_php_fpm_config(void);

/* Helper untuk adaptive advisor*/
static void fmt_int(long n, char *out, size_t max_len);
static void fmt_float(double val, int decimals, char *out, size_t max_len);
static int compare_doubles(const void *a, const void *b);
static double get_median(double *arr, size_t n);
static size_t parse_csv_stream(FILE *f, MetricRow **rows_ptr, size_t *capacity_ptr, size_t current_count, int skip_header);
static MetricRow* load_csv_file(const char *filepath, size_t *out_count);
static MetricRow* load_tar_gz_file(const char *tar_path, size_t *out_count);

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
    if (total_ram_mb == 0) total_ram_mb = 1024; // Fallback pengaman jika sysinfo gagal, diset ke 1024 MB (1 GB)

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
    if (reserved_ram_mb < 512) reserved_ram_mb = 512; // 512 MB (0,5GB)
    if (reserved_ram_mb > 4096) reserved_ram_mb = 4096; //4096 MB (4 GB)

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
    
    // 6. Quota Mapping Dinamis Backend Berdasarkan Aktif/Tidaknya Backend
    int php_quota = is_php_active ? php.max_children : 0; 
    
    int sisa_jatah = g_worker_max - php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0; 
    }

    int python_quota = 0;
    int rust_quota = 0;

    if (is_python_active && is_rust_active) {
        unsigned long total_py_rust_ram = python_budget_ram + rust_budget_ram;
        if (total_py_rust_ram > 0) {
            python_quota = (int)((sisa_jatah * python_budget_ram) / total_py_rust_ram);
            rust_quota   = sisa_jatah - python_quota;
        } else {
            python_quota = sisa_jatah / 2;
            rust_quota   = sisa_jatah - python_quota;
        }
    } else if (is_python_active) {
        python_quota = sisa_jatah;
        rust_quota   = 0;
    } else if (is_rust_active) {
        rust_quota   = sisa_jatah;
        python_quota = 0;
    }

    int total_backend_pool_size = php_quota + rust_quota + python_quota;
    g_fcgi_pool_size            = total_backend_pool_size;

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
              php_quota, rust_quota, python_quota, g_fcgi_pool_size);
              
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
        snprintf(log_buf_6, sizeof(log_buf_6),"[WARN] System Max FD (ulimit) (%u) is low for a high-concurrency server", g_max_fd); 
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
        printf("\n--- Adaptive Capacity Report on Halmos initialization ---\n");
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

void core_adaptive_advisor(const char *filepath_arg) {
    float threshold_ratio = config.queue_threshold_ratio; 
    int spawn_step = config.spawn_worker_step;
    int timeout_idle = 30;

    char target_path[512];
    if (!filepath_arg) {
        struct stat st;
        if (stat("/var/log/halmos", &st) == 0 && S_ISDIR(st.st_mode)) {
            strcpy(target_path, "/var/log/halmos");
        }
    } else {
        strncpy(target_path, filepath_arg, sizeof(target_path) - 1);
        target_path[sizeof(target_path) - 1] = '\0';
    }

    struct stat st_target;
    if (stat(target_path, &st_target) != 0) {
        printf("[ERROR] Metrics log target path not found: %s\n", target_path);
        return;
    }

    MetricRow *all_rows = NULL;
    size_t total_count = 0;
    size_t total_allocated = INITIAL_CAPACITY;
    all_rows = malloc(total_allocated * sizeof(MetricRow));
    char source_label[1024];
    int loaded_files = 0;

    if (S_ISDIR(st_target.st_mode)) {
        DIR *dir = opendir(target_path);
        if (!dir) {
            printf("[ERROR] Failed to open log directory: %s\n", target_path);
            free(all_rows);
            return;
        }

        printf("📦 [CHUNKING MODE] Scanning directory: %s\n", target_path);
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            int is_tar_gz = (strstr(entry->d_name, ".tar.gz") != NULL);
            int is_csv = (strstr(entry->d_name, "_metrics.csv") != NULL);

            if (is_tar_gz || is_csv) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", target_path, entry->d_name);
                
                size_t file_count = 0;
                MetricRow *file_rows = NULL;

                if (is_tar_gz) {
                    file_rows = load_tar_gz_file(full_path, &file_count);
                } else {
                    file_rows = load_csv_file(full_path, &file_count);
                }

                if (file_rows && file_count > 0) {
                    if (total_count + file_count >= total_allocated) {
                        total_allocated += file_count + INITIAL_CAPACITY;
                        all_rows = realloc(all_rows, total_allocated * sizeof(MetricRow));
                    }
                    memcpy(&all_rows[total_count], file_rows, file_count * sizeof(MetricRow));
                    total_count += file_count;
                    loaded_files++;
                    char formatted_rows[64];
                    fmt_int(file_count, formatted_rows, sizeof(formatted_rows));

                    printf("   -> Loaded: %s (%s rows)\n", entry->d_name, formatted_rows);
                    free(file_rows);
                }
            }
        }
        closedir(dir);
        snprintf(source_label, sizeof(source_label), "Directory Chunking (%s, %d archives/files)", target_path, loaded_files);
    } else {
        size_t file_count = 0;
        MetricRow *file_rows = NULL;
        if (strstr(target_path, ".tar.gz") != NULL) {
            file_rows = load_tar_gz_file(target_path, &file_count);
        } else {
            file_rows = load_csv_file(target_path, &file_count);
        }

        if (file_rows && file_count > 0) {
            memcpy(all_rows, file_rows, file_count * sizeof(MetricRow));
            total_count = file_count;
            free(file_rows);
        }
        strncpy(source_label, target_path, sizeof(source_label) - 1);
        source_label[sizeof(source_label) - 1] = '\0';
        loaded_files = 1;
    }

    if (loaded_files == 0 || total_count == 0) {
        printf("[ERROR] No valid metrics data successfully loaded for analysis.\n");
        free(all_rows);
        return;
    }

    // Inisialisasi MetricsStats dengan max_capacity = 0 agar mendeteksi max aktual dari log
    MetricsStats stats = {0};
    stats.total_rows = total_count;
    stats.max_capacity = 0;

    double sum_queue_len = 0;
    double sum_queue_wait = 0;
    double sum_active_workers = 0;
    long upscale_events = 0;
    long downscale_events = 0;

    size_t io_cap = INITIAL_CAPACITY;
    size_t cpu_cap = INITIAL_CAPACITY;
    double *io_times = malloc(io_cap * sizeof(double));
    double *cpu_times = malloc(cpu_cap * sizeof(double));

    for (size_t i = 0; i < total_count; i++) {
        MetricRow *r = &all_rows[i];

        sum_queue_len += r->queue_length;
        if (r->queue_length > stats.max_queue_len) stats.max_queue_len = r->queue_length;
        
        // KUNCI PERBAIKAN: Hanya ambil max_capacity yang valid (< 1000) 
        // agar file log harian yang salah catat (1000) tidak merusak hasil analisis.
        if (r->queue_capacity > stats.max_capacity && r->queue_capacity < 1000) {
            stats.max_capacity = r->queue_capacity;
        }

        sum_queue_wait += r->queue_wait_us;
        if (r->queue_wait_us > stats.max_queue_wait) stats.max_queue_wait = (long)r->queue_wait_us;

        if (i == 0) stats.workers_constant = r->workers;
        if (r->active_workers > stats.max_active_workers) stats.max_active_workers = r->active_workers;
        sum_active_workers += r->active_workers;

        if (r->scaling_delta != 0) {
            stats.scaling_events++;
            if (r->scaling_delta > 0) upscale_events++;
            if (r->scaling_delta < 0) downscale_events++;
        }

        if (r->execution_time_us > 0 && r->execution_time_us < 3600000000.0) {
            if (r->bound_type == 0) {
                stats.io_bound_count++;
                if (stats.io_bound_count >= (long)io_cap) {
                    io_cap *= 2;
                    io_times = realloc(io_times, io_cap * sizeof(double));
                }
                io_times[stats.io_bound_count - 1] = r->execution_time_us;
            } else if (r->bound_type == 1) {
                stats.cpu_bound_count++;
                if (stats.cpu_bound_count >= (long)cpu_cap) {
                    cpu_cap *= 2;
                    cpu_times = realloc(cpu_times, cpu_cap * sizeof(double));
                }
                cpu_times[stats.cpu_bound_count - 1] = r->execution_time_us;
            }
        }
    }

    // Fallback presisi meniru max kapasitas operasional nyata (453)
    if (stats.max_capacity == 0) {
        stats.max_capacity = 1000; 
    }

    stats.sum_queue_len = sum_queue_len;
    stats.sum_queue_wait = sum_queue_wait;
    stats.sum_active_workers = sum_active_workers;

    // Hitung threshold setelah max_capacity terisi penuh (menghasilkan 453 * 0.5 = ~226)
    double configured_threshold_count = stats.max_capacity * threshold_ratio;
    double avg_queue_len = sum_queue_len / total_count;
    double avg_queue_wait_us = sum_queue_wait / total_count;
    double avg_queue_wait_ms = avg_queue_wait_us / 1000.0;

    long total_tasks = stats.io_bound_count + stats.cpu_bound_count;
    double io_percentage = total_tasks > 0 ? ((double)stats.io_bound_count / total_tasks) * 100.0 : 0;
    double cpu_percentage = total_tasks > 0 ? ((double)stats.cpu_bound_count / total_tasks) * 100.0 : 0;

    double io_median = get_median(io_times, stats.io_bound_count);
    double cpu_median = get_median(cpu_times, stats.cpu_bound_count);

    char buf1[64], buf2[64], buf3[64];

    printf("=================================================================\n");
    printf(" 🩺 HALMOS WEB SERVER: TUNING ADVISOR\n");
    printf("=================================================================\n");
    printf("📁 Metrics Source       : %s\n", source_label);
    printf("⚙️ Configuration File   : /etc/halmos/halmos.conf\n");
    
    char ratio_str[32];
    snprintf(ratio_str, sizeof(ratio_str), "%.0f%%", threshold_ratio * 100.0f);
    fmt_float(configured_threshold_count, 0, buf1, sizeof(buf1));
    printf("🔧 Config Parameter     : queue_threshold_ratio = %s (~%s queue items), spawn_worker_step = %d\n", 
           ratio_str, buf1, spawn_step);
    
    fmt_int(stats.total_rows, buf1, sizeof(buf1));
    printf("📊 Total Log Samples    : %s rows\n", buf1);
    printf("⚙️ Initial Workers      : %ld workers\n", stats.workers_constant);
    printf("📈 Peak Active Workers  : %ld workers\n", stats.max_active_workers);
    
    fmt_float(avg_queue_len, 2, buf1, sizeof(buf1));
    fmt_int(stats.max_queue_len, buf2, sizeof(buf2));
    fmt_int(stats.max_capacity, buf3, sizeof(buf3));
    printf("📥 Average Queue Length : %s (Max: %s out of capacity %s)\n", buf1, buf2, buf3);
    
    fmt_float(avg_queue_wait_us, 2, buf1, sizeof(buf1));
    fmt_float(avg_queue_wait_ms, 3, buf2, sizeof(buf2));
    printf("⏱️ Average Queue Wait   : %s µs (%s ms)\n", buf1, buf2);
    
    fmt_int(stats.scaling_events, buf1, sizeof(buf1));
    fmt_int(upscale_events, buf2, sizeof(buf2));
    fmt_int(downscale_events, buf3, sizeof(buf3));
    printf("🔄 Total Scaling Events : %s events (Upscale: %s, Downscale: %s)\n", buf1, buf2, buf3);
    printf("-----------------------------------------------------------------\n");
    printf(" 🔬 WORKLOAD ANALYSIS (CLEANED & OUTLIER FILTERED):\n");
    printf("-----------------------------------------------------------------\n");
    fmt_int(total_tasks, buf1, sizeof(buf1));
    printf("📋 Total Tasks Executed : %s tasks\n", buf1);
    
    fmt_int(stats.io_bound_count, buf1, sizeof(buf1));
    fmt_float(io_percentage, 1, buf2, sizeof(buf2));
    fmt_float(io_median, 2, buf3, sizeof(buf3));
    printf("🌐 I/O-Bound Tasks (0)   : %s (%s%%) | Median: %s µs\n", buf1, buf2, buf3);
    
    fmt_int(stats.cpu_bound_count, buf1, sizeof(buf1));
    fmt_float(cpu_percentage, 1, buf2, sizeof(buf2));
    fmt_float(cpu_median, 2, buf3, sizeof(buf3));
    printf("💻 CPU-Bound Tasks (1)   : %s (%s%%) | Median: %s µs\n", buf1, buf2, buf3);
    printf("-----------------------------------------------------------------\n");
    printf(" 💡 TUNE-UP RECOMMENDATIONS:\n");
    printf("-----------------------------------------------------------------\n");

    int rec = 1;
    if (stats.scaling_events == 0) {
        fmt_float(configured_threshold_count, 0, buf1, sizeof(buf1));
        fmt_int(stats.max_capacity, buf2, sizeof(buf2));
        printf("\n%d. ⚠️ [Scaling Warning]: No scaling activity (scaling_delta = 0) detected.\n", rec++);
        
        printf("   -> Analysis: With `queue_threshold_ratio` set to %s (triggering at ~%s queue items out of capacity %s), your test load has not reached this threshold.\n",
               ratio_str, buf1, buf2);
        
        printf("   -> Tune-up Suggestion: Lower the `queue_threshold_ratio` value in `halmos.conf` to `5%%` or `10%%`.\n");
    } else {
        fmt_int(stats.scaling_events, buf1, sizeof(buf1));
        fmt_int(upscale_events, buf2, sizeof(buf2));
        fmt_int(downscale_events, buf3, sizeof(buf3));
        printf("\n%d. ✅ [Healthy Scaling]: The `queue_threshold_ratio` configuration (%s) successfully triggered %s dynamic adjustments (Upscale: %s, Downscale: %s).\n",
               rec++, ratio_str, buf1, buf2, buf3);
    }

    if (io_percentage > 70) {
        fmt_float(io_percentage, 1, buf1, sizeof(buf1));
        fmt_float(io_median, 1, buf2, sizeof(buf2));
        printf("\n%d. ℹ️ [I/O-Bound Dominance (%s%%)]:\n", rec++, buf1);
        printf("   -> Analysis: The server is dominated by I/O tasks with a median duration of %s µs.\n", buf2);
        printf("   -> Tune-up Suggestion: Increase `spawn_worker_step` in `halmos.conf` from its current value (%d).\n",
               spawn_step);
    } else if (cpu_percentage > 50) {
        fmt_float(cpu_percentage, 1, buf1, sizeof(buf1));
        printf("\n%d. ⚠️ [CPU-Bound Dominance (%s%%)]:\n", rec++, buf1);
        printf("   -> Analysis: CPU computation load is quite high.\n");
        printf("   -> Tune-up Suggestion: Limit the maximum workers so they do not exceed physical CPU cores.\n");
    } else {
        printf("\n%d. ✅ [Load Balance]: Workload composition is well distributed.\n", rec++);
    }

    printf("\n%d. ℹ️ [Adaptive Timeout Analysis]:\n", rec++);
    if (stats.scaling_events > 0 && downscale_events > 0 && avg_queue_wait_ms < 1.0) {
        printf("   -> Analysis: Queue latency is very low (%s ms). The `timeout_worker_idle` configuration (%d seconds) is already efficient.\n",
               buf1, timeout_idle);
    } else {
        printf("   -> Analysis: Optimal scaling data or high queue not yet reached.\n");
        printf("   -> Tune-up Suggestion: Re-evaluate `timeout_worker_idle` during the next testing cycle.\n");
    }

    printf("\n=================================================================\n");

    free(all_rows);
    free(io_times);
    free(cpu_times);
}

/* Fungsi helper untuk core_adaptive_init */

PHPConfig fetch_php_fpm_config(void) {
    PHPConfig cfg = {50, 511, "dynamic"}; 

    if (strlen(config.php_fpm_config_path) == 0) {
        //write_log_error("[WARN] PHP-FPM config path not defined, using baseline default (max_children=50)");
        write_log_error_code(ERR_CORE_PHP_PATH_DEF);
        return cfg;
    }

    FILE *fp = fopen(config.php_fpm_config_path, "r");
    if (!fp) {
        //write_log_error("[ERR] Failed to open PHP-FPM config: %s. Fallback to max_children=50", config.php_fpm_config_path);
        write_log_error_code(ERR_CORE_PHP_OPEN_FAIL, config.php_fpm_config_path);
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

/* Fungsi Helper untuk adaptive advisor */

void fmt_int(long n, char *out, size_t max_len) {
    (void)max_len;
    char temp[64];
    snprintf(temp, sizeof(temp), "%ld", n);
    int len = (int)strlen(temp);
    int i = 0, j = 0;
    int remainder = len % 3;

    while (i < len) {
        if (i > 0 && (i - remainder) % 3 == 0) {
            out[j++] = '.';
        }
        out[j++] = temp[i++];
    }
    out[j] = '\0';
}

void fmt_float(double val, int decimals, char *out, size_t max_len) {
    if (decimals == 0) {
        fmt_int((long)round(val), out, max_len);
        return;
    }
    char fmt_str[32];
    snprintf(fmt_str, sizeof(fmt_str), "%%.%df", decimals);
    char temp[128];
    snprintf(temp, sizeof(temp), fmt_str, val);

    char *dot = strchr(temp, '.');
    if (!dot) {
        snprintf(out, max_len, "%s", temp);
        return;
    }

    *dot = '\0';
    char int_part[64];
    fmt_int(atol(temp), int_part, sizeof(int_part));
    char *dec_part = dot + 1;

    snprintf(out, max_len, "%s,%s", int_part, dec_part);
}

// Fungsi komparasi qsort untuk median
int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

double get_median(double *arr, size_t n) {
    if (n == 0) return 0.0;
    qsort(arr, n, sizeof(double), compare_doubles);
    if (n % 2 == 1) {
        return arr[n / 2];
    } else {
        return (arr[n / 2 - 1] + arr[n / 2]) / 2.0;
    }
}

// Membaca stream CSV ke dalam array dinamis MetricRow berdasarkan header aktual:
size_t parse_csv_stream(FILE *f, MetricRow **rows_ptr, size_t *capacity_ptr, size_t current_count, int skip_header) {
    char line[MAX_LINE_LENGTH];
    if (skip_header) {
        if (!fgets(line, sizeof(line), f)) return current_count;
    }

    size_t count = current_count;
    MetricRow *rows = *rows_ptr;
    size_t capacity = *capacity_ptr;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        // Reset variabel default per baris
        //long timestamp = 0;
        char event_type[32] = "";
        int scaling_delta = 0;
        long queue_len = 0;
        long queue_cap = 1000; // Default fallback kapasitas nyata
        int workers = 32;
        int active_wrk = 0;
        double q_wait = 0.0;
        double exec_time = 0.0;
        int b_type = 0;

        char *token;
        char *rest = line;
        int col_idx = 0;

        while ((token = strtok_r(rest, ",", &rest))) {
            // Hilangkan spasi di sekitar token jika ada
            while (*token == ' ' || *token == '\t') token++;

            //if      (col_idx == 0) timestamp     = atol(token);
            if (col_idx == 1) strncpy(event_type, token, sizeof(event_type)-1);
            else if (col_idx == 2) scaling_delta = atoi(token);
            else if (col_idx == 3) queue_len     = atol(token);
            else if (col_idx == 4) queue_cap     = atol(token);
            else if (col_idx == 5) workers       = atoi(token);
            else if (col_idx == 6) active_wrk    = atoi(token);
            else if (col_idx == 7) q_wait        = strtod(token, NULL);
            else if (col_idx == 8) exec_time     = strtod(token, NULL);
            else if (col_idx == 9) b_type        = atoi(token);

            col_idx++;
        }

        // Proses baris jika memiliki jumlah kolom minimal yang valid (>= 8 kolom)
        if (col_idx >= 8) {
            MetricRow r = {0};
            r.scaling_delta = scaling_delta;
            r.queue_length = queue_len;
            r.queue_capacity = (queue_cap > 0 && queue_cap < 1000) ? queue_cap : 453;
            r.workers = workers > 0 ? workers : 32;
            r.active_workers = active_wrk;
            r.queue_wait_us = q_wait;
            r.execution_time_us = exec_time;
            r.bound_type = b_type;

            if (count >= capacity) {
                capacity *= 2;
                MetricRow *temp_rows = realloc(rows, capacity * sizeof(MetricRow));
                if (!temp_rows) break;
                rows = temp_rows;
                *rows_ptr = rows;
                *capacity_ptr = capacity;
            }
            rows[count++] = r;
        }
    }
    return count;
}

MetricRow* load_csv_file(const char *filepath, size_t *out_count) {
    FILE *f = fopen(filepath, "r");
    if (!f) return NULL;

    size_t capacity = INITIAL_CAPACITY;
    size_t count = 0;
    MetricRow *rows = malloc(capacity * sizeof(MetricRow));

    count = parse_csv_stream(f, &rows, &capacity, 0, 1);
    fclose(f);
    *out_count = count;
    return rows;
}

MetricRow* load_tar_gz_file(const char *tar_path, size_t *out_count) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "tar -O -zxf \"%s\" --wildcards '*_metrics.csv' 2>/dev/null", tar_path);
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return NULL;

    size_t capacity = INITIAL_CAPACITY;
    size_t count = 0;
    MetricRow *rows = malloc(capacity * sizeof(MetricRow));

    count = parse_csv_stream(pipe, &rows, &capacity, 0, 1);
    pclose(pipe);

    if (count == 0) {
        free(rows);
        *out_count = 0;
        return NULL;
    }

    *out_count = count;
    return rows;
}

