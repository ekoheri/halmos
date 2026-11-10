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


#define HISTORY_SLOTS 60 // Menyimpan 60 slot riwayat akses (misal per 60 detik atau per 1 menit)

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

// Gunakan atomic flag khusus untuk background loop adaptive
static atomic_bool g_adaptive_active = ATOMIC_VAR_INIT(false);
static pthread_t   g_runtime_adaptive_tid;

// --- 1. DOMAIN CORE / FRONTEND (Klien & Epoll) ---
uint32_t g_core_max_fd         = 0;
int      g_core_queue_capacity = 0;

// --- 2. DOMAIN WORKER THREAD POOL (Shared Workers) ---
int      g_worker_max          = 0;
int      g_worker_min          = 0;
int      g_event_batch_size    = 0;

// --- 3. DOMAIN BACKEND / FASTCGI UPSTREAM ---
int      g_fcgi_upstream_slots = 0;
int      g_fcgi_queue_capacity = 0;
int      g_fcgi_session_slots  = 0;

// --- 4. DOMAIN BACKEND UPSTREAM QUOTA untuk (PHP+Rust+Python) ---
int      g_fcgi_php_quota      = 0;
int      g_fcgi_rust_quota     = 0;
int      g_fcgi_python_quota   = 0;

// --- 5. RUNTIME OTONOM (In-Memory Self-Tuning Variables) ---
static float    g_runtime_queue_threshold_ratio = 0.50f;
static int      g_runtime_spawn_worker_step     = 4;
static int      g_runtime_timeout_worker_idle   = 30;


extern volatile sig_atomic_t server_running;

extern TaskQueue global_queue;

/* Helper untuk adaptive init*/

static char* trim_string_safe(char *str);

static PHPConfig fetch_php_fpm_config(void);

// --- 1. Deteksi Hardware & Sistem Operasi ---
static HardwareProfile detect_hardware(void);

// --- 2. Kalkulasi Anggaran RAM Berdasarkan Backend Aktif ---
static MemoryBudget calculate_memory_budgets(const HardwareProfile *hw);

// --- 3. Kalkulasi Kapasitas Worker Pool ---
static WorkerCapacity calculate_worker_capacity(const HardwareProfile *hw, const MemoryBudget *mb);

// --- 4. Kalkulasi Qoota Backend (fatsCG) ---
static BackendQuotas calculate_backend_quotas(const HardwareProfile *hw, const MemoryBudget *mb, const WorkerCapacity *wc);

// --- 5. menulis ke log atau menampilkan perhitungan adaptive ke monitor
static void core_print_adaptive_summary(
    const HardwareProfile *hw, 
    const MemoryBudget *mb, 
    const WorkerCapacity *wc, 
    const PHPConfig *php, 
    bool is_php_active, 
    int print_to_terminal
);

/* Helper untuk adaptive runtime*/
static void core_adaptive_set_policy(float threshold, int spawn_step, int timeout_idle);

static uint64_t timespec_diff_us(const struct timespec *start, const struct timespec *end);

static void runtime_record_task(uint64_t total_cpu_us, uint64_t total_wall_us, uint64_t resumes);

static void* runtime_autoscale_evaluator(void *arg);

/********************************************************************
 * BAGIAN A: STARTUP HARDWARE-AWARE INITIALIZATION
 ********************************************************************/

void core_adaptive_hw_aware_init(int print_to_terminal) {
    // 1. Eksekusi tahapan modular secara berurutan
    HardwareProfile hw = detect_hardware();
    MemoryBudget mb = calculate_memory_budgets(&hw);
    WorkerCapacity wc = calculate_worker_capacity(&hw, &mb);
    BackendQuotas quotas = calculate_backend_quotas(&hw, &mb, &wc);
    
    // Status backend untuk keperluan logging/audit
    bool is_php_active = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    PHPConfig php = is_php_active ? fetch_php_fpm_config() : (PHPConfig){0};
    
    // 2. Assign langsung ke variabel global Halmos
    g_core_max_fd         = hw.max_fd;
    g_worker_max          = wc.worker_max;
    g_worker_min          = wc.worker_min;
    g_event_batch_size    = wc.event_batch_size;
    g_core_queue_capacity = wc.core_queue_capacity;
    
    g_fcgi_php_quota      = quotas.php_quota;
    g_fcgi_rust_quota     = quotas.rust_quota;
    g_fcgi_python_quota   = quotas.python_quota;
    g_fcgi_upstream_slots = quotas.total_upstream_slots;
    g_fcgi_queue_capacity = quotas.upstream_queue_capacity;
    g_fcgi_session_slots  = quotas.session_slots;

    // 3. Eksekusi pelaporan/logging
    core_print_adaptive_summary(&hw, &mb, &wc, &php, is_php_active, print_to_terminal);
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

// Setter (Opsional, jika ada modul lain yang butuh override kebijakan)
void core_adaptive_set_policy(float threshold, int spawn_step, int timeout_idle) {
    pthread_mutex_lock(&g_runtime_win.lock);
    g_runtime_queue_threshold_ratio = threshold;
    g_runtime_spawn_worker_step     = spawn_step;
    g_runtime_timeout_worker_idle   = timeout_idle;
    pthread_mutex_unlock(&g_runtime_win.lock);
}

// Snapshot Getter (Aman & Konsisten)
AdaptivePolicy core_adaptive_get_policy(void) {
    AdaptivePolicy policy;
    pthread_mutex_lock(&g_runtime_win.lock);
    policy.threshold_ratio = g_runtime_queue_threshold_ratio;
    policy.spawn_step     = g_runtime_spawn_worker_step;
    policy.timeout_idle   = g_runtime_timeout_worker_idle;
    pthread_mutex_unlock(&g_runtime_win.lock);
    return policy;
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

HardwareProfile detect_hardware(void) {
    HardwareProfile hw;
    
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
    
    hw.num_cores = (detected_cores < 1) ? 1 : (int)detected_cores;


    // --- 2. DETEKSI FILE DESCRIPTOR LIMIT (RLIMIT) ---
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        rl.rlim_cur = 4096;
    }
    
    if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > UINT32_MAX) {
        hw.max_fd = 65536;
    } else {
        hw.max_fd = (uint32_t)rl.rlim_cur;
    }
    if (hw.max_fd < 64) hw.max_fd = 64;


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
        hw.total_ram_mb = container_ram_mb;
    } else {
        // Fallback: Baca dari sysinfo (fisik host)
        struct sysinfo si;
        if (sysinfo(&si) != 0) {
            memset(&si, 0, sizeof(si));
        }
        hw.total_ram_mb = (unsigned long)((si.totalram * si.mem_unit) / (1024 * 1024));
        if (hw.total_ram_mb == 0) hw.total_ram_mb = 1024; // Fallback 1GB
    }

    return hw;
}

MemoryBudget calculate_memory_budgets(const HardwareProfile *hw) {
    MemoryBudget mb;
    
    // Cadangan untuk OS & Database (25%, min 512MB, maks 4096MB)
    // 1. Hitung cadangan normal (25%, min 512MB)
    mb.reserved_ram_mb = hw->total_ram_mb / 4;
    if (mb.reserved_ram_mb < 512) mb.reserved_ram_mb = 512;
    if (mb.reserved_ram_mb > 4096) mb.reserved_ram_mb = 4096;

    // 2. Jika total RAM ternyata lebih kecil dari cadangan minimum yang diminta...
    if (hw->total_ram_mb <= mb.reserved_ram_mb) {
        // Jangan diset 0! Berikan porsi minimum yang aman untuk web (misal 64 MB, 
        // atau sisa dari total RAM dikurangi porsi OS yang sangat kecil).
        if (hw->total_ram_mb > 64) {
            mb.available_for_web_mb = hw->total_ram_mb - 64; // Sisakan 64MB untuk OS
            mb.reserved_ram_mb = 64;
        } else {
            // Jika server benar-benar "kentang" (< 64MB total RAM)
            mb.available_for_web_mb = 32; // Paksa jatah minimum web 32MB
            mb.reserved_ram_mb = hw->total_ram_mb > 32 ? hw->total_ram_mb - 32 : 8;
        }
    } else {
        // Jalur normal (aman dari underflow)
        mb.available_for_web_mb = hw->total_ram_mb - mb.reserved_ram_mb;
    }

    // Cek status backend aktif
    bool is_php    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    int active_count = (is_php ? 1 : 0) + (is_python ? 1 : 0) + (is_rust ? 1 : 0);
    if (active_count == 0) active_count = 1;

    // Alokasi proporsional sederhana (bisa diperluas dengan sistem weight)
    mb.php_budget_mb = 0;
    mb.python_budget_mb = 0;
    mb.rust_budget_mb = 0;

    if (active_count == 3) {
        mb.php_budget_mb    = (mb.available_for_web_mb * 50) / 100;
        mb.python_budget_mb = (mb.available_for_web_mb * 30) / 100;
        mb.rust_budget_mb   = (mb.available_for_web_mb * 20) / 100;
    } else if (active_count == 2) {
        if (is_php && is_python) {
            mb.php_budget_mb    = (mb.available_for_web_mb * 60) / 100;
            mb.python_budget_mb = (mb.available_for_web_mb * 40) / 100;
        } else if (is_php && is_rust) {
            mb.php_budget_mb    = (mb.available_for_web_mb * 70) / 100;
            mb.rust_budget_mb   = (mb.available_for_web_mb * 30) / 100;
        } else if (is_python && is_rust) {
            mb.python_budget_mb = (mb.available_for_web_mb * 60) / 100;
            mb.rust_budget_mb   = (mb.available_for_web_mb * 40) / 100;
        }
    } else {
        if (is_php)    mb.php_budget_mb    = mb.available_for_web_mb;
        if (is_python) mb.python_budget_mb = mb.available_for_web_mb;
        if (is_rust)   mb.rust_budget_mb   = mb.available_for_web_mb;
    }

    return mb;
}

WorkerCapacity calculate_worker_capacity(const HardwareProfile *hw, const MemoryBudget *mb) {
    WorkerCapacity wc;
    
    // Batas kapasitas maksimum berdasarkan core (misal 32 atau 64 per core)
    int cpu_based_max = (int)(hw->num_cores * 32);
    
    // Asumsi rata-rata konsumsi per proses backend (dalam MB)
    int php_mem    = (config.php.memory_budget > 0) ? config.php.memory_budget : 20;
    int python_mem = (config.python.memory_budget > 0) ? config.python.memory_budget : 40;
    int rust_mem   = (config.rust.memory_budget > 0) ? config.rust.memory_budget : 15;

    int max_by_ram = (php_mem > 0 ? (int)(mb->php_budget_mb / php_mem) : 0) +
                     (python_mem > 0 ? (int)(mb->python_budget_mb / python_mem) : 0) +
                     (rust_mem > 0 ? (int)(mb->rust_budget_mb / rust_mem) : 0);

    // --- PENYESUAIAN BATAS MINIMUM DINAMIS (RAMAH HARDWARE KECIL) ---
    // Tentukan lantai minimum mutlak: 2 worker untuk 1 core, atau minimal 4 untuk multi-core
    int absolute_min_workers = (hw->num_cores < 2) ? 2 : 4;

    // Jika kapasitas berdasarkan RAM sangat kecil, jangan dipaksa 32, 
    // cukup ikuti absolute_min_workers agar server tetap bisa menyala.
    if (max_by_ram < absolute_min_workers) {
        max_by_ram = absolute_min_workers;
    }

    int recommended = (cpu_based_max < max_by_ram) ? cpu_based_max : max_by_ram;
    if (recommended > 1024) recommended = 1024;
    if (recommended < absolute_min_workers) recommended = absolute_min_workers;

    wc.worker_max = recommended;
    
    // Worker minimum proporsional terhadap core, dibatasi tidak melebihi worker_max
    wc.worker_min = (int)hw->num_cores * 2;
    if (wc.worker_min < absolute_min_workers) wc.worker_min = absolute_min_workers;
    if (wc.worker_min > wc.worker_max) wc.worker_min = wc.worker_max;

    wc.event_batch_size = (wc.worker_max > MAX_EVENT_BATCH_SIZE) ? MAX_EVENT_BATCH_SIZE : wc.worker_max;

    if (hw->max_fd > (uint32_t)(wc.worker_max > 0 ? wc.worker_max : 0)) {
        uint32_t sisa_fd = hw->max_fd - (uint32_t)wc.worker_max;
        wc.core_queue_capacity = (int)((sisa_fd * 60U) / 100U);
    } else {
        wc.core_queue_capacity = 256;
    }

    if (wc.core_queue_capacity > MAX_QUEUE_CAPACITY) wc.core_queue_capacity = MAX_QUEUE_CAPACITY;
    if (wc.core_queue_capacity < 256) wc.core_queue_capacity = 256;

    return wc;
}

BackendQuotas calculate_backend_quotas(const HardwareProfile *hw, const MemoryBudget *mb, const WorkerCapacity *wc) {
    BackendQuotas quotas = {0};

    // Cek status backend aktif
    bool is_php_active    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python_active = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust_active   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    PHPConfig php = is_php_active ? fetch_php_fpm_config() : (PHPConfig){0};

    // --- PERBAIKAN POIN 7: BATASI PHP QUOTA AGAR TIDAK MELEBIHI WORKER_MAX ---
    int php_target = is_php_active ? php.max_children : 0;
    if (php_target > wc->worker_max) {
        quotas.php_quota = wc->worker_max;
    } else {
        quotas.php_quota = php_target;
    }
    
    int sisa_jatah = wc->worker_max - quotas.php_quota;
    if (sisa_jatah < 0) {
        sisa_jatah = 0; 
    }

    int python_quota = 0;
    int rust_quota = 0;

    if (is_python_active && is_rust_active) {
        unsigned long total_py_rust_ram = mb->python_budget_mb + mb->rust_budget_mb;
        if (total_py_rust_ram > 0) {
            python_quota = (int)((sisa_jatah * mb->python_budget_mb) / total_py_rust_ram);
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

    quotas.python_quota = python_quota;
    quotas.rust_quota   = rust_quota;

    quotas.total_upstream_slots = quotas.php_quota + quotas.python_quota + quotas.rust_quota;
    if (quotas.total_upstream_slots < 32) {
        quotas.total_upstream_slots = 32;
    }

    int upstream_sisa = wc->worker_max - quotas.total_upstream_slots;
    quotas.upstream_queue_capacity = (upstream_sisa > 0) ? (int)((upstream_sisa * 50U) / 100U) : 128;
    if (quotas.upstream_queue_capacity < 64) {
        quotas.upstream_queue_capacity = 64;
    }

    // --- HITUNG ADAPTIVE FCGI SESSION POOL SLOTS (Pengali Konservatif) ---
    // pengali 8 slot per core CPU
    int min_safe_sessions = (int)(hw->num_cores * 8); 
    
    // Pastikan batas minimal pengaman tidak kurang dari 64 atau 128
    if (min_safe_sessions < 64) {
        min_safe_sessions = 64;
    }

    //Angka ideal ambil 50% dari upstream slot
    int calculated_sessions = (quotas.total_upstream_slots * 50) / 100;
    
    if (calculated_sessions < min_safe_sessions) {
        quotas.session_slots = min_safe_sessions;
    } else if (calculated_sessions > wc->worker_max) {
        quotas.session_slots = wc->worker_max; 
    } else {
        quotas.session_slots = calculated_sessions;
    }

    // --- PERBAIKAN POIN 6: BATAS MUTLAK SESSION SLOTS TIDAK BOLEH > WORKER_MAX ---
    if (quotas.session_slots > wc->worker_max) {
        quotas.session_slots = wc->worker_max;
    }

    return quotas;
}

void core_print_adaptive_summary(
    const HardwareProfile *hw, 
    const MemoryBudget *mb, 
    const WorkerCapacity *wc, 
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
              hw->num_cores, hw->total_ram_mb, hw->max_fd);

    // 2. Workers & Queue Capacity Summary
    snprintf(log_buf_2, sizeof(log_buf_2), "[CORE] Workers (Min/Recommended Ceiling): %d/%d | Event Batch: %d | Core Queue Capacity: %d", 
              wc->worker_min, wc->worker_max, wc->event_batch_size, wc->core_queue_capacity);
    
    // 3. Upstream Slots Allocation Summary
    snprintf(log_buf_3, sizeof(log_buf_3), "[UPSTREAM] Slots Allocation -> PHP: %d | Rust: %d | Python: %d | Total Upstream Slots: %d | Total Session Slots: %d ", 
              g_fcgi_php_quota, g_fcgi_rust_quota, g_fcgi_python_quota, g_fcgi_upstream_slots, g_fcgi_session_slots);
              
    // 4. Memory Budget Awareness (Pengganti log_buf_mem)
    snprintf(log_buf_4, sizeof(log_buf_4), "[MEM] Budget Awareness -> Reserved (OS/DB): %lu MB | Available for Web: %lu MB [PHP Budget: %lu MB, Python Budget: %lu MB, Rust Budget: %lu MB]", 
              mb->reserved_ram_mb, mb->available_for_web_mb, mb->php_budget_mb, mb->python_budget_mb, mb->rust_budget_mb);

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
    if (hw->max_fd < 1024) {
        snprintf(log_buf_7, sizeof(log_buf_7), "[WARN] Core Max FD (ulimit) (%u) is low for a high-concurrency server", hw->max_fd); 
    }

    // 8 - 12. Audit PHP-FPM Configuration
    if (is_php_active) {
        if (php->max_children > wc->worker_max) {
            snprintf(log_buf_8, sizeof(log_buf_8), "[WARN] PHP-FPM max_children (%d) exceeds hardware-aware worker baseline (%d)", 
                      php->max_children, wc->worker_max); 
            snprintf(log_buf_9, sizeof(log_buf_9), "[ADVICE] Action: Review PHP-FPM max_children in '%s' if resource contention occurs", 
                      config.php_fpm_config_path);          
        } 
        else if (php->max_children < (wc->worker_max / 4)) {
            int suggested_max = wc->worker_max / 2;
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
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores < 1) n_cores = 1; 
    int high_load_threshold = (int)(n_cores * 2);

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

        // --- EVALUASI UTAMA DENGAN HYSSTERESIS & ANTREAN ---
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
