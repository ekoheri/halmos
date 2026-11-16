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
#include <signal.h>
#include <stdatomic.h>
#include <time.h>


#define HISTORY_SLOTS 120 //60 // Menyimpan 60 slot riwayat akses (misal per 60 detik atau per 1 menit)

typedef struct {
    uint64_t io_counts[HISTORY_SLOTS];
    uint64_t cpu_counts[HISTORY_SLOTS];
    int current_index;
    pthread_mutex_t lock;
} RuntimeMetricsWindow;

static RuntimeMetricsWindow g_runtime_win;

typedef struct {
    int max_children;
    int backlog;
    char mode[16]; 
} PHPConfig;

AdaptiveHardwareAware adaptive_hw_aware = {0};

// Gunakan atomic flag khusus untuk background loop adaptive
static atomic_bool g_adaptive_active = ATOMIC_VAR_INIT(false);
static pthread_t   g_runtime_adaptive_tid;

// --- 5. RUNTIME OTONOM (In-Memory Self-Tuning Variables) ---
static AdaptivePolicy current_policy = {
    .threshold_ratio = 0.50f,
    .spawn_step     = 4,
    .timeout_idle   = 30
};


extern volatile sig_atomic_t server_running;

extern TaskQueue global_queue;

/* Helper untuk adaptive init*/

static char* trim_string_safe(char *str);

static PHPConfig fetch_php_fpm_config(void);

// --- 1. Deteksi Hardware & Sistem Operasi ---
static void detect_hardware(void);

// --- 2. Kalkulasi Anggaran RAM Berdasarkan Backend Aktif ---
static void calculate_memory_budgets(void);

// --- 3. Kalkulasi Kapasitas Worker Pool ---
static void calculate_worker_capacity(void);

// --- 4. Kalkulasi Qoota Backend (fatsCG) ---
static void calculate_backend_quotas(void);

// --- 5. menulis ke log atau menampilkan perhitungan adaptive ke monitor
static void core_print_adaptive_summary(
    const PHPConfig *php, 
    bool is_php_active, 
    int print_to_terminal
);

/* Helper untuk adaptive runtime*/
static void core_adaptive_set_policy(float threshold, int spawn_step, int timeout_idle);

static uint64_t timespec_diff_us(const struct timespec *start, const struct timespec *end);

static void core_adaptive_set_policy(float threshold, int spawn_step, int timeout_idle);

static void runtime_record_task(uint64_t total_cpu_us, uint64_t total_wall_us, uint64_t resumes);

static void* runtime_autoscale_evaluator(void *arg);

/********************************************************************
 * BAGIAN A: STARTUP HARDWARE-AWARE INITIALIZATION
 ********************************************************************/

void core_adaptive_hw_aware_init(int print_to_terminal) {
    // 1. Eksekusi tahapan modular secara berurutan
    detect_hardware();
    calculate_memory_budgets();
    calculate_worker_capacity();
    calculate_backend_quotas();
    
    // Status backend untuk keperluan logging/audit
    bool is_php_active = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    PHPConfig php = is_php_active ? fetch_php_fpm_config() : (PHPConfig){0};
    
    // 3. Eksekusi pelaporan/logging
    core_print_adaptive_summary(&php, is_php_active, print_to_terminal);
}

/********************************************************************
 * BAGIAN B: RUNTIME IN-MEMORY SELF-TUNING ENGINE
 ********************************************************************/
// Inisialisasi mutex & langsung spawn background thread secara otonom
bool core_adaptive_runtime_init(void) {
    memset(&g_runtime_win, 0, sizeof(RuntimeMetricsWindow));
    g_runtime_win.current_index = 0;
    
    if (pthread_mutex_init(&g_runtime_win.lock, NULL) != 0) {
        write_log("[ERROR] Failed to initialize runtime adaptive mutex.");
        return false;
    }

    atomic_store(&g_adaptive_active, true);

    if (pthread_create(&g_runtime_adaptive_tid, NULL, runtime_autoscale_evaluator, NULL) != 0) {
        write_log("[ERROR] Failed to start runtime adaptive background thread.");
        pthread_mutex_destroy(&g_runtime_win.lock);
        atomic_store(&g_adaptive_active, false);
        return false;
    }
    return true;
}

// Snapshot Getter
AdaptivePolicy core_adaptive_get_policy(void) {
    AdaptivePolicy return_policy;
    pthread_mutex_lock(&g_runtime_win.lock);
    return_policy = current_policy;
    pthread_mutex_unlock(&g_runtime_win.lock);
    return return_policy;
}

// Fungsi untuk membersihkan sumber daya runtime adaptive saat server shutdown
void core_adaptive_runtime_destroy(void) {
    // 1. Matikan flag background loop
    atomic_store(&g_adaptive_active, false);

    // 2. Tunggu thread benar-benar mati (Join) sebelum mutex didestruksi!
    pthread_join(g_runtime_adaptive_tid, NULL);

    // 3. Setelah thread mati, aman untuk mendestruksi mutex
    pthread_mutex_destroy(&g_runtime_win.lock);
    write_log("[ADAPTIVE RAM] Runtime self-tuning engine destroyed cleanly.");
}

// 1. SATU FUNGSI UNTUK MEMULAI TICK (Otomatis inisialisasi jika baru, sekaligus catat CPU tick)
void core_adaptive_telemetry_tick_begin(AdaptiveTelemetry *t, struct timespec *cpu_start) {
    if (!t || !cpu_start) return;
    
    // Jika struct belum pernah diinisialisasi (pertama kali request masuk)
    if (t->wall_start.tv_sec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &t->wall_start);
        t->total_cpu_time_us = 0;
        t->resume_count = 0;
    }
    
    // Selalu catat waktu awal CPU untuk slice/resume kali ini
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, cpu_start);
}

// 2. SATU FUNGSI UNTUK MENGAKHIRI TICK (Hitung CPU & tambah resume_count)
void core_adaptive_telemetry_tick_end(AdaptiveTelemetry *t, struct timespec *cpu_start) {
    if (!t || !cpu_start) return;
    
    struct timespec cpu_end;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end);
    
    t->total_cpu_time_us += timespec_diff_us(cpu_start, &cpu_end);
    t->resume_count++; // Otomatis terhitung per eksekusi event loop
}

// 3. FINALISASI AKHIR (Saat request benar-benar tuntas/mati)
void core_adaptive_telemetry_finalize(AdaptiveTelemetry *t) {
    if (!t || t->wall_start.tv_sec == 0) return;

    struct timespec wall_end;
    clock_gettime(CLOCK_MONOTONIC, &wall_end);
    
    uint64_t total_wall_time_us = timespec_diff_us(&t->wall_start, &wall_end);
    uint64_t total_cpu_us       = t->total_cpu_time_us;
    uint64_t resumes            = t->resume_count;

    // Cetak log terpusat
    //fprintf(stderr, "[TELEMETRY %s] Wall: %lu us | CPU: %lu us | Resumes: %lu\n", 
    //         proto_name, total_wall_time_us, total_cpu_us, resumes);

    // Suapi ke RuntimeMetricsWindow (60 slot history Anda)
    runtime_record_task(total_cpu_us, total_wall_time_us, resumes);
}

/* Fungsi helper untuk core_adaptive_hw_aware_init */

// Fungsi bantu untuk membersihkan spasi di awal dan akhir string (in-place trim)
char* trim_string_safe(char *str) {
    if (!str) return NULL;
    while (*str && (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n')) {
        str++;
    }
    if (*str == '\0') return str;

    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        end--;
    }
    *(end + 1) = '\0';
    return str;
}

PHPConfig fetch_php_fpm_config(void) {
    PHPConfig cfg = {50, 511, "dynamic"}; 

    if (strlen(config.php_fpm_config_path) == 0) {
        write_log_error_code(ERR_CORE_PHP_PATH_DEF);
        return cfg;
    }

    FILE *fp = fopen(config.php_fpm_config_path, "r");
    if (!fp) {
        write_log_error_code(ERR_CORE_PHP_OPEN_FAIL, config.php_fpm_config_path);
        return cfg;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // 1. Bersihkan newline / carriage return di akhir baris
        line[strcspn(line, "\r\n")] = '\0';

        char *ptr = line;

        // 2. Buang komentar inline (simbol ';' atau '#')
        char *comment = strchr(ptr, ';');
        if (!comment) comment = strchr(ptr, '#');
        if (comment) *comment = '\0';

        // 3. Trim spasi awal baris
        ptr = trim_string_safe(ptr);

        // 4. Lewati baris kosong atau baris komentar penuh
        if (*ptr == '\0' || *ptr == ';' || *ptr == '#') continue;

        // 5. Parse pm.max_children dengan aman
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
        // 6. Parse listen.backlog dengan aman
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
        // 7. Parse mode pm (dynamic / static / ondemand)
        else if (strstr(ptr, "pm") && !strchr(ptr, '.')) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                // Pastikan key benar-benar "pm" (bukan awalan dari pm.max_children dsb)
                *eq = '\0';
                char *key_part = trim_string_safe(ptr);
                if (strcmp(key_part, "pm") == 0) {
                    char *val_part = trim_string_safe(eq + 1);
                    if (strlen(val_part) > 0) {
                        snprintf(cfg.mode, sizeof(cfg.mode), "%s", val_part);
                    }
                }
                *eq = '='; // Kembalikan tanda sama dengan untuk keamanan (opsional)
            }
        }
    }
    fclose(fp);
    return cfg;
}

void detect_hardware(void) {
    // --- 1. DETEKSI JUMLAH CORE (CPU) DENGAN DUKUNGAN CGROUPS ---
    long detected_cores = 0;
    
    // Coba baca Cgroups v2 (cpu.max)
    FILE *f_cpuv2 = fopen("/sys/fs/cgroup/cpu.max", "r");
    if (f_cpuv2) {
        char quota_str[32] = {0};
        char period_str[32] = {0};
        if (fscanf(f_cpuv2, "%31s %31s", quota_str, period_str) == 2) {
            if (strcmp(quota_str, "max") != 0) {
                long quota = atol(quota_str);
                long period = atol(period_str);
                if (quota > 0 && period > 0) {
                    detected_cores = (quota + period - 1) / period; // Pembulatan ke atas
                }
            }
        }
        fclose(f_cpuv2);
    }

    // Jika cgroups v2 tidak ada/unlimited, coba Cgroups v1 (cpu.cfs_quota_us & period_us)
    if (detected_cores <= 0) {
        FILE *f_quota = fopen("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "r");
        FILE *f_period = fopen("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "r");
        if (f_quota && f_period) {
            long quota, period;
            if (fscanf(f_quota, "%ld", &quota) == 1 && fscanf(f_period, "%ld", &period) == 1) {
                if (quota > 0 && period > 0) {
                    detected_cores = (quota + period - 1) / period;
                }
            }
        }
        if (f_quota) fclose(f_quota);
        if (f_period) fclose(f_period);
    }

    // Fallback terakhir: Baca core online dari sistem host
    if (detected_cores <= 0) {
        detected_cores = sysconf(_SC_NPROCESSORS_ONLN);
    }
    
    adaptive_hw_aware.num_cores = (detected_cores < 1) ? 1 : (int)detected_cores;


    // --- 2. DETEKSI FILE DESCRIPTOR LIMIT (RLIMIT) ---
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        rl.rlim_cur = 4096;
    }
    
    if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > UINT32_MAX) {
        adaptive_hw_aware.max_fd = 65536;
    } else {
        adaptive_hw_aware.max_fd = (uint32_t)rl.rlim_cur;
    }
    if (adaptive_hw_aware.max_fd < 64) adaptive_hw_aware.max_fd = 64;


    // --- 3. DETEKSI RAM DENGAN DUKUNGAN CGROUPS ---
    unsigned long container_ram_mb = 0;

    // Coba baca Cgroups v2 (memory.max)
    FILE *f_memv2 = fopen("/sys/fs/cgroup/memory.max", "r");
    if (f_memv2) {
        char mem_str[64] = {0};
        if (fscanf(f_memv2, "%63s", mem_str) == 1) {
            if (strcmp(mem_str, "max") != 0) {
                unsigned long long mem_bytes = strtoull(mem_str, NULL, 10);
                // Batas wajar (hindari angka max integer 64-bit yang merepresentasikan tak terhingga)
                if (mem_bytes > 0 && mem_bytes < 0x7FFFFFFFFFFFFFFFULL) {
                    container_ram_mb = (unsigned long)(mem_bytes / (1024ULL * 1024ULL));
                }
            }
        }
        fclose(f_memv2);
    }

    // Jika cgroups v2 tidak ada/unlimited, coba Cgroups v1 (memory.limit_in_bytes)
    if (container_ram_mb == 0) {
        FILE *f_memv1 = fopen("/sys/fs/cgroup/memory/memory.limit_in_bytes", "r");
        if (f_memv1) {
            unsigned long long mem_bytes = 0;
            if (fscanf(f_memv1, "%llu", &mem_bytes) == 1) {
                // Cgroups v1 bernilai sangat besar (> 9000 PB) jika tidak dibatasi
                if (mem_bytes > 0 && mem_bytes < 9000000000000000ULL) {
                    container_ram_mb = (unsigned long)(mem_bytes / (1024ULL * 1024ULL));
                }
            }
            fclose(f_memv1);
        }
    }

    // Jika cgroups mendeteksi batas RAM yang valid, gunakan itu
    if (container_ram_mb > 0) {
        adaptive_hw_aware.total_ram_mb = container_ram_mb;
    } else {
        // Fallback: Baca dari sysinfo (fisik host)
        struct sysinfo si;
        if (sysinfo(&si) != 0) {
            memset(&si, 0, sizeof(si));
        }
        adaptive_hw_aware.total_ram_mb = (unsigned long)((si.totalram * si.mem_unit) / (1024 * 1024));
        if (adaptive_hw_aware.total_ram_mb == 0) adaptive_hw_aware.total_ram_mb = 1024; // Fallback 1GB
    }
}

void calculate_memory_budgets() {
    // 1. Tentukan persentase jatah untuk Web Server (Default 50%)
    unsigned long web_percent = 50; 

    if (config.web_server_reserved_ram > 0) {
        web_percent = config.web_server_reserved_ram;
        
        // Batasan pengaman agar persentase tidak keblabasan (min 10%, max 90%)
        if (web_percent > 90) web_percent = 90;
        if (web_percent < 10) web_percent = 10;
    }

    // Hitung jatah RAM web server berdasarkan persentase dari config
    unsigned long web_budget_mb = (adaptive_hw_aware.total_ram_mb * web_percent) / 100;
    adaptive_hw_aware.reserved_ram_mb = adaptive_hw_aware.total_ram_mb - web_budget_mb;

    // Batas bawah minimal cadangan OS 512MB (kecuali RAM server di bawah itu)
    if (adaptive_hw_aware.reserved_ram_mb < 512 && adaptive_hw_aware.total_ram_mb >= 512) {
        adaptive_hw_aware.reserved_ram_mb = 512;
        web_budget_mb = adaptive_hw_aware.total_ram_mb - adaptive_hw_aware.reserved_ram_mb; // Sesuaikan kembali jatah web
    }
    
    // Pengaman batas maksimal cadangan OS (misal dibatasi maksimal 90% dari total RAM)
    unsigned long max_allowed_reserve = (adaptive_hw_aware.total_ram_mb * 90) / 100;
    if (adaptive_hw_aware.reserved_ram_mb > max_allowed_reserve) {
        adaptive_hw_aware.reserved_ram_mb = max_allowed_reserve;
        web_budget_mb = adaptive_hw_aware.total_ram_mb - adaptive_hw_aware.reserved_ram_mb;
    }

    // 2. Jika total RAM ternyata lebih kecil dari cadangan minimum yang diminta...
    if (adaptive_hw_aware.total_ram_mb <= adaptive_hw_aware.reserved_ram_mb) {
        if (adaptive_hw_aware.total_ram_mb > 64) {
            adaptive_hw_aware.available_for_web_mb = adaptive_hw_aware.total_ram_mb - 64; // Sisakan 64MB untuk OS
            adaptive_hw_aware.reserved_ram_mb = 64;
        } else {
            // Jika server benar-benar "kentang" (< 64MB total RAM)
            adaptive_hw_aware.available_for_web_mb = 32; 
            adaptive_hw_aware.reserved_ram_mb = adaptive_hw_aware.total_ram_mb > 32 ? adaptive_hw_aware.total_ram_mb - 32 : 8;
        }
    } else {
        // Jalur normal (aman dari underflow)
        adaptive_hw_aware.available_for_web_mb = web_budget_mb;
    }

    // Cek status backend aktif
    bool is_php    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    int active_count = (is_php ? 1 : 0) + (is_python ? 1 : 0) + (is_rust ? 1 : 0);
    if (active_count == 0) active_count = 1;

    // Alokasi proporsional backend
    adaptive_hw_aware.php_budget_mb = 0;
    adaptive_hw_aware.python_budget_mb = 0;
    adaptive_hw_aware.rust_budget_mb = 0;

    if (active_count == 3) {
        adaptive_hw_aware.php_budget_mb    = (adaptive_hw_aware.available_for_web_mb * 50) / 100;
        adaptive_hw_aware.python_budget_mb = (adaptive_hw_aware.available_for_web_mb * 30) / 100;
        adaptive_hw_aware.rust_budget_mb   = (adaptive_hw_aware.available_for_web_mb * 20) / 100;
    } else if (active_count == 2) {
        if (is_php && is_python) {
            adaptive_hw_aware.php_budget_mb    = (adaptive_hw_aware.available_for_web_mb * 60) / 100;
            adaptive_hw_aware.python_budget_mb = (adaptive_hw_aware.available_for_web_mb * 40) / 100;
        } else if (is_php && is_rust) {
            adaptive_hw_aware.php_budget_mb    = (adaptive_hw_aware.available_for_web_mb * 70) / 100;
            adaptive_hw_aware.rust_budget_mb   = (adaptive_hw_aware.available_for_web_mb * 30) / 100;
        } else if (is_python && is_rust) {
            adaptive_hw_aware.python_budget_mb = (adaptive_hw_aware.available_for_web_mb * 60) / 100;
            adaptive_hw_aware.rust_budget_mb   = (adaptive_hw_aware.available_for_web_mb * 40) / 100;
        }
    } else {
        if (is_php)    adaptive_hw_aware.php_budget_mb    = adaptive_hw_aware.available_for_web_mb;
        if (is_python) adaptive_hw_aware.python_budget_mb = adaptive_hw_aware.available_for_web_mb;
        if (is_rust)   adaptive_hw_aware.rust_budget_mb   = adaptive_hw_aware.available_for_web_mb;
    }
}

void calculate_worker_capacity(void) {
    // Batas kapasitas maksimum berdasarkan core (misal 32 atau 64 per core)
    int cpu_based_max = (int)(adaptive_hw_aware.num_cores * 32);
    
    // Konversi budget RAM sistem dari MB (dari struct mb) ke Byte penuh
    size_t php_budget_bytes    = (size_t)adaptive_hw_aware.php_budget_mb * 1024 * 1024;
    size_t python_budget_bytes = (size_t)adaptive_hw_aware.python_budget_mb * 1024 * 1024;
    size_t rust_budget_bytes   = (size_t)adaptive_hw_aware.rust_budget_mb * 1024 * 1024;

    // Ambil langsung dari config yang sudah murni byte (dengan fallback aman jika 0)
    size_t php_mem    = (config.php.memory_budget > 0) ? (size_t)config.php.memory_budget : (20UL * 1024 * 1024);
    size_t python_mem = (config.python.memory_budget > 0) ? (size_t)config.python.memory_budget : (40UL * 1024 * 1024);
    size_t rust_mem   = (config.rust.memory_budget > 0) ? (size_t)config.rust.memory_budget : (15UL * 1024 * 1024);

    // KELIRUAN SEBELUMNYA DIPERBAIKI DI SINI: Byte dibagi dengan Byte!
    int max_by_ram = (php_mem > 0 ? (int)(php_budget_bytes / php_mem) : 0) +
                     (python_mem > 0 ? (int)(python_budget_bytes / python_mem) : 0) +
                     (rust_mem > 0 ? (int)(rust_budget_bytes / rust_mem) : 0);

    // --- PENYESUAIAN BATAS MINIMUM DINAMIS (RAMAH HARDWARE KECIL) ---
    int absolute_min_workers = (adaptive_hw_aware.num_cores < 2) ? 2 : 4;

    if (max_by_ram < absolute_min_workers) {
        max_by_ram = absolute_min_workers;
    }

    int recommended = (cpu_based_max < max_by_ram) ? cpu_based_max : max_by_ram;
    if (recommended > 1024) recommended = 1024;
    if (recommended < absolute_min_workers) recommended = absolute_min_workers;

    adaptive_hw_aware.worker_max = recommended;
    
    adaptive_hw_aware.worker_min = (int)adaptive_hw_aware.num_cores * 2;
    if (adaptive_hw_aware.worker_min < absolute_min_workers) adaptive_hw_aware.worker_min = absolute_min_workers;
    if (adaptive_hw_aware.worker_min > adaptive_hw_aware.worker_max) adaptive_hw_aware.worker_min = adaptive_hw_aware.worker_max;

    adaptive_hw_aware.event_batch_size = (adaptive_hw_aware.worker_max > MAX_EVENT_BATCH_SIZE) ? MAX_EVENT_BATCH_SIZE : adaptive_hw_aware.worker_max;

    if (adaptive_hw_aware.max_fd > (uint32_t)(adaptive_hw_aware.worker_max > 0 ? adaptive_hw_aware.worker_max : 0)) {
        uint32_t sisa_fd = adaptive_hw_aware.max_fd - (uint32_t)adaptive_hw_aware.worker_max;
        adaptive_hw_aware.core_queue_capacity = (int)((sisa_fd * 60U) / 100U);
    } else {
        adaptive_hw_aware.core_queue_capacity = 256;
    }

    if (adaptive_hw_aware.core_queue_capacity > MAX_QUEUE_CAPACITY) adaptive_hw_aware.core_queue_capacity = MAX_QUEUE_CAPACITY;
    if (adaptive_hw_aware.core_queue_capacity < 256) adaptive_hw_aware.core_queue_capacity = 256;
}

void calculate_backend_quotas(void) {
    // Cek status backend aktif
    bool is_php_active    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python_active = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust_active   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    PHPConfig php = is_php_active ? fetch_php_fpm_config() : (PHPConfig){0};

    // --- PERBAIKAN POIN 7: BATASI PHP QUOTA AGAR TIDAK MELEBIHI WORKER_MAX ---
    int php_target = is_php_active ? php.max_children : 0;
    if (php_target > adaptive_hw_aware.worker_max) {
        adaptive_hw_aware.php_quota = adaptive_hw_aware.worker_max;
    } else {
        adaptive_hw_aware.php_quota = php_target;
    }
    
    int sisa_jatah = adaptive_hw_aware.worker_max - adaptive_hw_aware.php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0; 
    }

    int python_quota = 0;
    int rust_quota = 0;

    if (is_python_active && is_rust_active) {
        unsigned long total_py_rust_ram = adaptive_hw_aware.python_budget_mb + adaptive_hw_aware.rust_budget_mb;
        if (total_py_rust_ram > 0) {
            python_quota = (int)((sisa_jatah *adaptive_hw_aware.python_budget_mb) / total_py_rust_ram);
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

    adaptive_hw_aware.python_quota = python_quota;
    adaptive_hw_aware.rust_quota   = rust_quota;

    adaptive_hw_aware.total_upstream_slots = adaptive_hw_aware.php_quota + adaptive_hw_aware.python_quota + adaptive_hw_aware.rust_quota;
    if (adaptive_hw_aware.total_upstream_slots < 32) {
        adaptive_hw_aware.total_upstream_slots = 32;
    }

    int upstream_sisa = adaptive_hw_aware.worker_max - adaptive_hw_aware.total_upstream_slots;
    adaptive_hw_aware.upstream_queue_capacity = (upstream_sisa > 0) ? (int)((upstream_sisa * 50U) / 100U) : 128;
    if (adaptive_hw_aware.upstream_queue_capacity < 64) {
        adaptive_hw_aware.upstream_queue_capacity = 64;
    }

    // --- HITUNG ADAPTIVE FCGI SESSION POOL SLOTS (Pengali Konservatif) ---
    // pengali 8 slot per core CPU
    int min_safe_sessions = (int)(adaptive_hw_aware.num_cores * 8); 
    
    // Pastikan batas minimal pengaman tidak kurang dari 64 atau 128
    if (min_safe_sessions < 64) {
        min_safe_sessions = 64;
    }

    //Angka ideal ambil 50% dari upstream slot
    int calculated_sessions = (adaptive_hw_aware.total_upstream_slots * 50) / 100;
    
    if (calculated_sessions < min_safe_sessions) {
        adaptive_hw_aware.fcgi_session_slots = min_safe_sessions;
    } else if (calculated_sessions > adaptive_hw_aware.worker_max) {
        adaptive_hw_aware.fcgi_session_slots = adaptive_hw_aware.worker_max; 
    } else {
        adaptive_hw_aware.fcgi_session_slots = calculated_sessions;
    }

    // --- PERBAIKAN POIN 6: BATAS MUTLAK SESSION SLOTS TIDAK BOLEH > WORKER_MAX ---
    if (adaptive_hw_aware.fcgi_session_slots > adaptive_hw_aware.worker_max) {
        adaptive_hw_aware.fcgi_session_slots = adaptive_hw_aware.worker_max;
    }

}

void core_print_adaptive_summary(
    const PHPConfig *php, 
    bool is_php_active, 
    int print_to_terminal
) {
    char log_buf_1[256] = "";
    char log_buf_2[256] = "";
    char log_buf_3[256] = "";
    char log_buf_4[256] = ""; // Untuk log_buf_mem
    char log_buf_5[256] = ""; // Advisory ulimit 1
    char log_buf_6[256] = ""; // Advisory ulimit 2
    char log_buf_7[256] = ""; // Core Max FD warning
    char log_buf_8[256] = ""; // PHP-FPM max_children warning
    char log_buf_9[1024] = ""; // PHP-FPM max_children advice action
    char log_buf_10[256] = ""; // PHP-FPM conservative notice
    char log_buf_11[1024] = ""; // PHP-FPM scale advice action
    char log_buf_12[256] = ""; // PHP-FPM supporting config tip

    // 1. Hardware Initialization Summary
    snprintf(log_buf_1, sizeof(log_buf_1), "[CORE] Hardware-Aware Init -> Cores: %ld | RAM: %lu MB | Core Max FD: %u", 
              adaptive_hw_aware.num_cores, adaptive_hw_aware.total_ram_mb, adaptive_hw_aware.max_fd);

    // 2. Workers & Queue Capacity Summary
    snprintf(log_buf_2, sizeof(log_buf_2), "[CORE] Workers (Min/Recommended Ceiling): %d/%d | Event Batch: %d | Core Queue Capacity: %d", 
              adaptive_hw_aware.worker_min, adaptive_hw_aware.worker_max, adaptive_hw_aware.event_batch_size, adaptive_hw_aware.core_queue_capacity);
    
    // 3. Upstream Slots Allocation Summary
    snprintf(log_buf_3, sizeof(log_buf_3), "[UPSTREAM] Slots Allocation -> PHP: %d (From max_children) | Rust: %d | Python: %d | Total Upstream Slots: %d | Total Session Slots: %d ", 
              adaptive_hw_aware.php_quota, adaptive_hw_aware.rust_quota, adaptive_hw_aware.python_quota, adaptive_hw_aware.total_upstream_slots, adaptive_hw_aware.fcgi_session_slots);
              
    // 4. Memory Budget Awareness (Pengganti log_buf_mem)
    snprintf(log_buf_4, sizeof(log_buf_4), "[MEM] Budget Awareness -> Reserved (OS/DB): %lu MB | Available for Web: %lu MB [PHP Budget: %lu MB, Python Budget: %lu MB, Rust Budget: %lu MB]", 
              adaptive_hw_aware.reserved_ram_mb, adaptive_hw_aware.available_for_web_mb, adaptive_hw_aware.php_budget_mb, adaptive_hw_aware.python_budget_mb, adaptive_hw_aware.rust_budget_mb);

    // 5 & 6. Advisory Ulimit
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) { rl.rlim_cur = 4096; }
    rlim_t min_safe_ulimit = 4096;
    if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < min_safe_ulimit) {
        snprintf(log_buf_5, sizeof(log_buf_5), "[WARN] System Max FD/ulimit = %lu is relatively low for high-concurrency workloads (recommended baseline: %lu)",
                  (unsigned long)rl.rlim_cur, (unsigned long)min_safe_ulimit);          
        snprintf(log_buf_6, sizeof(log_buf_6), "[ADVICE] Consider increasing ulimit (e.g. run 'ulimit -n 4096' or configure limits.conf)");           
    }

    // 7. Core Max FD Warning
    if (adaptive_hw_aware.max_fd < 1024) {
        snprintf(log_buf_7, sizeof(log_buf_7), "[WARN] Core Max FD (ulimit) (%u) is low for a high-concurrency server", adaptive_hw_aware.max_fd); 
    }

    // 8 - 12. Audit PHP-FPM Configuration
    if (is_php_active) {
        if (php->max_children > adaptive_hw_aware.worker_max) {
            snprintf(log_buf_8, sizeof(log_buf_8), "[WARN] PHP-FPM max_children (%d) exceeds hardware-aware worker baseline (%d)", 
                      php->max_children, adaptive_hw_aware.worker_max); 
            snprintf(log_buf_9, sizeof(log_buf_9), "[ADVICE] Action: Review PHP-FPM max_children in '%s' if resource contention occurs", 
                      config.php_fpm_config_path);          
        } 
        else if (php->max_children < (adaptive_hw_aware.worker_max / 4)) {
            int suggested_max = adaptive_hw_aware.worker_max / 2;
            int suggested_start = suggested_max / 4;
            int suggested_min = suggested_start;
            int suggested_max_spare = suggested_max / 2;

            snprintf(log_buf_10, sizeof(log_buf_10), "[ADVICE] PHP-FPM max_children (%d) is conservative for detected hardware", 
                        php->max_children);
            snprintf(log_buf_11, sizeof(log_buf_11), "[ADVICE] Action: Consider scaling pool in '%s' up to max_children = %d based on PHP workload", 
                      config.php_fpm_config_path, suggested_max);  
            snprintf(log_buf_12, sizeof(log_buf_12), "[ADVICE] Supporting Config Tip -> Adjust pm.start_servers = %d, min_spare = %d, max_spare = %d accordingly", 
                      suggested_start, suggested_min, suggested_max_spare);                     
        }
    }

    // --- Cetak Berdasarkan print_to_terminal ---
    if (print_to_terminal == 0) {
        if (log_buf_1[0] != '\0')  write_log("%s", log_buf_1);
        if (log_buf_2[0] != '\0')  write_log("%s", log_buf_2);
        if (log_buf_3[0] != '\0')  write_log("%s", log_buf_3);
        if (log_buf_4[0] != '\0')  write_log("%s", log_buf_4);
        if (log_buf_5[0] != '\0')  write_log("%s", log_buf_5);
        if (log_buf_6[0] != '\0')  write_log("%s", log_buf_6);
        if (log_buf_7[0] != '\0')  write_log("%s", log_buf_7);
        if (log_buf_8[0] != '\0')  write_log("%s", log_buf_8);
        if (log_buf_9[0] != '\0')  write_log("%s", log_buf_9);
        if (log_buf_10[0] != '\0') write_log("%s", log_buf_10);
        if (log_buf_11[0] != '\0') write_log("%s", log_buf_11);
        if (log_buf_12[0] != '\0') write_log("%s", log_buf_12);
    } else {
        printf("\n--- Adaptive Capacity Report on Halmos initialization ---\n");
        if (log_buf_1[0] != '\0')  printf("%s\n", log_buf_1);
        if (log_buf_2[0] != '\0')  printf("%s\n", log_buf_2);
        if (log_buf_3[0] != '\0')  printf("%s\n", log_buf_3);
        if (log_buf_4[0] != '\0')  printf("%s\n", log_buf_4);
        if (log_buf_5[0] != '\0')  printf("%s\n", log_buf_5);
        if (log_buf_6[0] != '\0')  printf("%s\n", log_buf_6);
        if (log_buf_7[0] != '\0')  printf("%s\n", log_buf_7);
        if (log_buf_8[0] != '\0')  printf("%s\n", log_buf_8);
        if (log_buf_9[0] != '\0')  printf("%s\n", log_buf_9);
        if (log_buf_10[0] != '\0') printf("%s\n", log_buf_10);
        if (log_buf_11[0] != '\0') printf("%s\n", log_buf_11);
        if (log_buf_12[0] != '\0') printf("%s\n", log_buf_12);
        printf("---------------------------------------\n");
    }
}

/* Fungsi helper untuk adative runtime autoscale */
uint64_t timespec_diff_us(const struct timespec *start, const struct timespec *end) {
    int64_t sec = end->tv_sec - start->tv_sec;
    int64_t nsec = end->tv_nsec - start->tv_nsec;

    if (nsec < 0) {
        sec--;
        nsec += 1000000000LL;
    }

    return (uint64_t)(sec * 1000000LL + nsec / 1000LL);
}

// Setter (Opsional, jika ada modul lain yang butuh override kebijakan)
void core_adaptive_set_policy(float threshold, int spawn_step, int timeout_idle) {
    pthread_mutex_lock(&g_runtime_win.lock);
    current_policy.threshold_ratio = threshold;
    current_policy.spawn_step      = spawn_step;
    current_policy.timeout_idle    = timeout_idle;
    pthread_mutex_unlock(&g_runtime_win.lock);
}

// Pencatatan Task (Langsung diakumulasi ke slot waktu aktif saat ini)
void runtime_record_task(uint64_t total_cpu_us, uint64_t total_wall_us, uint64_t resumes) {
    if (total_wall_us == 0) return;

    double cpu_ratio = (double)total_cpu_us / (double)total_wall_us;
    
    // Kriteria baru yang lebih kaya:
    // - Jika CPU memakan > 40% waktu -> CPU-bound (1)
    // - Atau jika resumes sangat tinggi (misal > 50 kali resume meskipun CPU kecil) -> Ini murni Heavy I/O / Network Waiting (0)
    int bound_type = 0;
    if (cpu_ratio > 0.40) {
        bound_type = 1; // CPU-bound
    } else if (resumes > 50) {
        bound_type = 0; // Heavy I/O-bound (banyak tertahan non-blocking yield)
    } else {
        bound_type = 0; // Fast / Normal I/O
    }
    
    pthread_mutex_lock(&g_runtime_win.lock);
    int idx = g_runtime_win.current_index;
    if (idx >= 0 && idx < HISTORY_SLOTS) {
        if (bound_type == 1) {
            g_runtime_win.cpu_counts[idx]++;
        } else {
            g_runtime_win.io_counts[idx]++;
        }
    }
    pthread_mutex_unlock(&g_runtime_win.lock);
}

// Background Loop yang Bergeser Mengikuti Slot Waktu (Sliding Window)
void* runtime_autoscale_evaluator(void *arg) {
    (void)arg;

    // Deteksi jumlah core sekali saja saat awal loop
    int num_cores = (adaptive_hw_aware.num_cores > 0) ? adaptive_hw_aware.num_cores : 1;
    int high_load_threshold = num_cores * 2;

    while (atomic_load(&g_adaptive_active)) {
        // Tidur per 1 detik yang dipecah menjadi interval 100ms agar responsif saat shutdown
        for (int i = 0; i < 10 && atomic_load(&g_adaptive_active); i++) {
            usleep(100000); // 100ms * 10 = 1 detik
        }
        if (!atomic_load(&g_adaptive_active)) break;

        // 1. Ambil dan reset window metrik dengan penguncian mutex window
        pthread_mutex_lock(&g_runtime_win.lock);
        int latest_idx = g_runtime_win.current_index;
        g_runtime_win.current_index = (g_runtime_win.current_index + 1) % HISTORY_SLOTS;
        
        int next_idx = g_runtime_win.current_index;
        g_runtime_win.cpu_counts[next_idx] = 0;
        g_runtime_win.io_counts[next_idx] = 0;

        double weighted_cpu_sum = 0.0;
        double weighted_io_sum = 0.0;
        double total_weight = 0.0;

        for (int i = 0; i < HISTORY_SLOTS; i++) {
            int target_idx = (latest_idx - i + HISTORY_SLOTS) % HISTORY_SLOTS;
            double weight = (double)(HISTORY_SLOTS - i); 

            weighted_cpu_sum += (double)g_runtime_win.cpu_counts[target_idx] * weight;
            weighted_io_sum  += (double)g_runtime_win.io_counts[target_idx] * weight;
            total_weight     += weight;
        }
        pthread_mutex_unlock(&g_runtime_win.lock);

        // 2. Ambil policy saat ini sebagai referensi/status aktif
        AdaptivePolicy current_policy = core_adaptive_get_policy();

        // 3. Ambil kondisi antrean saat ini secara aman
        pthread_mutex_lock(&global_queue.lock);
        int current_count   = global_queue.count;
        int max_limit       = global_queue.max_queue_limit;
        int total_workers   = global_queue.total_workers;
        int active_workers  = global_queue.active_workers;
        pthread_mutex_unlock(&global_queue.lock);

        float load_factor = (max_limit > 0) ? (float)current_count / max_limit : 0;
        
        // Hitung rasio utilisasi worker (0.0 hingga 1.0+)
        float worker_utilization = (total_workers > 0) ? (float)active_workers / total_workers : 0.0f;

        // Inisialisasi nilai baru mengikuti nilai saat ini (agar stabil jika tidak ada perubahan)
        float new_threshold = current_policy.threshold_ratio;
        int new_spawn_step  = current_policy.spawn_step;
        int new_timeout     = current_policy.timeout_idle;

        // --- DEFINISI BATAS HYSSTERESIS ---
        // Atas (Scale-Up Trigger) = 0.60, Bawah (Scale-Down Trigger) = 0.40
        float upper_limit = 0.60f;
        float lower_limit = 0.40f;

        // --- EVALUASI UTAMA DENGAN HYSSTERESIS & WORKER UTILIZATION ---
        if (load_factor >= upper_limit || current_count > high_load_threshold || worker_utilization >= 0.85f) {
            // Kondisi High Load: Antrean penuh, atau worker hampir 100% sibuk
            new_timeout = 300; // Tahan worker lebih lama agar tidak cepat didrop
        } 
        else if (load_factor <= lower_limit && current_count == 0 && worker_utilization <= 0.30f) {
            // Kondisi Normal / Idle: Antrean kosong & utilisasi worker di bawah 30%
            new_timeout = 30;
            
            // Evaluasi karakteristik CPU vs IO dari metrik saat benar-benar idle
            if (total_weight > 0.0) {
                double final_cpu_score = weighted_cpu_sum / total_weight;
                double final_io_score  = weighted_io_sum / total_weight;
                double total_score     = final_cpu_score + final_io_score;

                if (total_score >= 1.0) {
                    float cpu_ratio = (float)(final_cpu_score / total_score);
                    float io_ratio  = (float)(final_io_score / total_score);

                    if (cpu_ratio > 0.5f) {
                        new_threshold = 0.35f;
                        new_spawn_step  = 2;
                    } 
                    else if (io_ratio > 0.8f) {
                        new_threshold = 0.60f;
                        new_spawn_step  = 4;
                    } else {
                        new_threshold = 0.50f;
                        new_spawn_step  = 4;
                    }
                }
            }
        }
        else if (current_count > 0 || worker_utilization > 0.30f) {
            // Light load / zona transisi hysteresis
            new_timeout = 60;
        }
        // JIKA DI ZONA AMAN HYSTERESIS (antara 0.40 dan 0.60 tanpa lonjakan): 
        // Variabel new_timeout dan new_threshold dipertahankan seperti nilai sebelumnya (tidak flapping).

        // --- SIMPAN KEBIJAKAN BARU JIKA ADA PERUBAHAN (MENGHINDARI WRITE SIA-SIA) ---
        if (new_threshold != current_policy.threshold_ratio ||
            new_spawn_step  != current_policy.spawn_step ||
            new_timeout     != current_policy.timeout_idle) {
            core_adaptive_set_policy(new_threshold, new_spawn_step, new_timeout);
        }
    }
    return NULL;
}
