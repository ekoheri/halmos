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

#define INITIAL_CAPACITY 1000
#define MAX_LINE_LENGTH 1024

#define HISTORY_SLOTS 60 // Menyimpan 60 slot riwayat akses (misal per detik atau per menit)

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
float    g_runtime_queue_threshold_ratio = 0.50f; // Default 50%
int      g_runtime_spawn_worker_step     = 4;     // Default step 4 worker
int      g_runtime_timeout_worker_idle   = 30;    // Default 30 detik

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

extern volatile sig_atomic_t server_running;

extern TaskQueue global_queue;

/* Helper untuk adaptive init*/
static PHPConfig fetch_php_fpm_config(void);

// --- 1. Deteksi Hardware & Sistem Operasi ---
static HardwareProfile core_detect_hardware(void);

// --- 2. Kalkulasi Anggaran RAM Berdasarkan Backend Aktif ---
static MemoryBudget core_calculate_memory_budgets(const HardwareProfile *hw);

// --- 3. Kalkulasi Kapasitas Worker Pool ---
static WorkerCapacity core_calculate_worker_capacity(const HardwareProfile *hw, const MemoryBudget *mb);

// --- 4. Kalkulasi Qoota Backend (fatsCG) ---
static BackendQuotas core_calculate_backend_quotas(const HardwareProfile *hw, const MemoryBudget *mb, const WorkerCapacity *wc);

// --- 5. menulis ke log atau menampilkan perhitungan adaptive ke monitor
static void core_print_adaptive_summary(
    const HardwareProfile *hw, 
    const MemoryBudget *mb, 
    const WorkerCapacity *wc, 
    const PHPConfig *php, 
    bool is_php_active, 
    int print_to_terminal
);

/********************************************************************
 * BAGIAN A: STARTUP HARDWARE-AWARE INITIALIZATION
 ********************************************************************/

void core_adaptive_hw_aware_init(int print_to_terminal) {
    // 1. Eksekusi tahapan modular secara berurutan
    HardwareProfile hw = core_detect_hardware();
    MemoryBudget mb = core_calculate_memory_budgets(&hw);
    WorkerCapacity wc = core_calculate_worker_capacity(&hw, &mb);
    BackendQuotas quotas = core_calculate_backend_quotas(&hw, &mb, &wc);
    
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

    if (pthread_create(&g_runtime_adaptive_tid, NULL, core_adaptive_runtime_background_loop, NULL) != 0) {
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

// Pencatatan Task (Langsung diakumulasi ke slot waktu aktif saat ini)

void core_adaptive_runtime_record_task(uint64_t execution_time_us) {
    // Tentukan sendiri secara otomatis: > 10ms (10000 us) dianggap CPU-bound
    int bound_type = (execution_time_us > 10000) ? 1 : 0; 
    
    pthread_mutex_lock(&g_runtime_win.lock);
    int idx = g_runtime_win.current_index;
    if (bound_type == 1) {
        g_runtime_win.cpu_counts[idx]++;
    } else {
        g_runtime_win.io_counts[idx]++;
    }
    pthread_mutex_unlock(&g_runtime_win.lock);
}

// Background Loop yang Bergeser Mengikuti Slot Waktu (Sliding Window)
void* core_adaptive_runtime_background_loop(void *arg) {
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

        if (total_weight == 0.0) continue;

        double final_cpu_score = weighted_cpu_sum / total_weight;
        double final_io_score  = weighted_io_sum / total_weight;
        double total_score     = final_cpu_score + final_io_score;

        if (total_score < 1.0) continue;

        float cpu_ratio = (float)(final_cpu_score / total_score);
        float io_ratio  = (float)(final_io_score / total_score);

        // --- AMBIL KONDISI ANTREAN SAAT INI SECARA AMAN DENGAN MUTEX QUEUE ---
        pthread_mutex_lock(&global_queue.lock);
        int current_count = global_queue.count;
        int max_limit = global_queue.max_queue_limit;
        pthread_mutex_unlock(&global_queue.lock);

        float load_factor = (max_limit > 0) ? (float)current_count / max_limit : 0;

        // --- PENYESUAIAN OTONOM GABUNGAN (TREN BEBAN + KONDISI QUEUE) ---
        pthread_mutex_lock(&g_runtime_win.lock);
        if (load_factor > g_runtime_queue_threshold_ratio || current_count > high_load_threshold) {
            // Kondisi High Load / Padat: Tahan worker lebih lama (misal 300 detik)
            g_runtime_timeout_worker_idle = 300;
        } 
        else if (current_count > 0) {
            // Kondisi Light Load / Ada sisa task: (misal 60 detik)
            g_runtime_timeout_worker_idle = 60;
        } 
        else {
            // Kondisi Idle / Sepi, disesuaikan juga dengan karakteristik CPU vs IO
            if (cpu_ratio > 0.5f) {
                g_runtime_queue_threshold_ratio = 0.35f;
                g_runtime_spawn_worker_step     = 2;
                g_runtime_timeout_worker_idle   = 30; // CPU idle cepat dibersihkan
            } 
            else if (io_ratio > 0.8f) {
                g_runtime_queue_threshold_ratio = 0.60f;
                g_runtime_spawn_worker_step     = 4;
                g_runtime_timeout_worker_idle   = 45; // I/O biarkan tahan agak lama
            } 
            else {
                g_runtime_queue_threshold_ratio = 0.50f;
                g_runtime_spawn_worker_step     = 4;
                g_runtime_timeout_worker_idle   = 30;
            }
        }
        pthread_mutex_unlock(&g_runtime_win.lock);
    }
    return NULL;
}

// --- THREAD-SAFE GETTERS UNTUK VARIABEL OTONOM ---
int core_adaptive_get_timeout_idle(void) {
    pthread_mutex_lock(&g_runtime_win.lock);
    int val = g_runtime_timeout_worker_idle;
    pthread_mutex_unlock(&g_runtime_win.lock);
    return val;
}

int core_adaptive_get_spawn_step(void) {
    pthread_mutex_lock(&g_runtime_win.lock);
    int val = g_runtime_spawn_worker_step;
    pthread_mutex_unlock(&g_runtime_win.lock);
    return val;
}

float core_adaptive_get_threshold_ratio(void) {
    pthread_mutex_lock(&g_runtime_win.lock);
    float val = g_runtime_queue_threshold_ratio;
    pthread_mutex_unlock(&g_runtime_win.lock);
    return val;
}

/* Fungsi helper untuk core_adaptive_hw_aware_init */

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

HardwareProfile core_detect_hardware(void) {
    HardwareProfile hw;
    hw.num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (hw.num_cores < 1) hw.num_cores = 1;

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

    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        memset(&si, 0, sizeof(si));
    }
    hw.total_ram_mb = (unsigned long)((si.totalram * si.mem_unit) / (1024 * 1024));
    if (hw.total_ram_mb == 0) hw.total_ram_mb = 1024; // Fallback 1GB

    return hw;
}

MemoryBudget core_calculate_memory_budgets(const HardwareProfile *hw) {
    MemoryBudget mb;
    
    // Cadangan untuk OS & Database (25%, min 512MB, maks 4096MB)
    mb.reserved_ram_mb = hw->total_ram_mb / 4;
    if (mb.reserved_ram_mb < 512) mb.reserved_ram_mb = 512;
    if (mb.reserved_ram_mb > 4096) mb.reserved_ram_mb = 4096;

    mb.available_for_web_mb = hw->total_ram_mb - mb.reserved_ram_mb;

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

WorkerCapacity core_calculate_worker_capacity(const HardwareProfile *hw, const MemoryBudget *mb) {
    WorkerCapacity wc;
    
    int cpu_based_max = (int)(hw->num_cores * 64);
    
    // Asumsi rata-rata konsumsi per proses backend
    int php_mem    = (config.php.memory_budget > 0) ? config.php.memory_budget : 20;
    int python_mem = (config.python.memory_budget > 0) ? config.python.memory_budget : 40;
    int rust_mem   = (config.rust.memory_budget > 0) ? config.rust.memory_budget : 15;

    int max_by_ram = (php_mem > 0 ? (int)(mb->php_budget_mb / php_mem) : 0) +
                     (python_mem > 0 ? (int)(mb->python_budget_mb / python_mem) : 0) +
                     (rust_mem > 0 ? (int)(mb->rust_budget_mb / rust_mem) : 0);

    if (max_by_ram < 32) max_by_ram = 32;

    int recommended = (cpu_based_max < max_by_ram) ? cpu_based_max : max_by_ram;
    if (recommended > 1024) recommended = 1024;
    if (recommended < 32) recommended = 32;

    wc.worker_max = recommended;
    wc.worker_min = (int)hw->num_cores * 4;
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

BackendQuotas core_calculate_backend_quotas(const HardwareProfile *hw, const MemoryBudget *mb, const WorkerCapacity *wc) {
    BackendQuotas quotas = {0};

    // Cek status backend aktif
    bool is_php_active    = (config.php.node_count > 0 || strlen(config.php_fpm_config_path) > 0);
    bool is_python_active = (config.python.node_count > 0 || strlen(config.python.ext) > 0);
    bool is_rust_active   = (config.rust.node_count > 0 || strlen(config.rust.ext) > 0);

    PHPConfig php = is_php_active ? fetch_php_fpm_config() : (PHPConfig){0};

    quotas.php_quota = is_php_active ? php.max_children : 0;
    
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
