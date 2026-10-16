#include "halmos_core_admission.h"
#include "halmos_global.h" // Mengambil semua variabel global termasuk g_queue_capacity

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    bool valid;
} CpuStats;

static CpuStats read_cpu_stats() {
    CpuStats stats = { .valid = false };
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return stats;
    
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp)) {
        int matched = sscanf(buffer, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
                             &stats.user, &stats.nice, &stats.system, &stats.idle,
                             &stats.iowait, &stats.irq, &stats.softirq, &stats.steal);
        if (matched >= 4) {
            stats.valid = true;
        }
    }
    fclose(fp);
    return stats;
}

static bool calculate_cpu_percentage(CpuStats *prev, CpuStats *curr, float *out_usage) {
    if (!prev->valid || !curr->valid) return false;
    
    unsigned long long prev_idle = prev->idle + prev->iowait;
    unsigned long long curr_idle = curr->idle + curr->iowait;
    
    unsigned long long prev_non_idle = prev->user + prev->nice + prev->system + prev->irq + prev->softirq + prev->steal;
    unsigned long long curr_non_idle = curr->user + curr->nice + curr->system + curr->irq + curr->softirq + curr->steal;
    
    unsigned long long prev_total = prev_idle + prev_non_idle;
    unsigned long long curr_total = curr_idle + curr_non_idle;
    
    if (curr_total < prev_total || curr_idle < prev_idle) return false;
    
    unsigned long long total_d = curr_total - prev_total;
    unsigned long long idle_d = curr_idle - prev_idle;
    
    if (total_d == 0) return false;
    
    *out_usage = (float)(total_d - idle_d) / (float)total_d;
    return true;
}

static float get_system_ram_usage() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0.0f;
    
    unsigned long total_kb = 0, available_kb = 0;
    char line[128];
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %lu kB", &total_kb) == 1) continue;
        if (sscanf(line, "MemAvailable: %lu kB", &available_kb) == 1) continue;
    }
    fclose(fp);
    
    if (total_kb == 0) return 0.0f;
    unsigned long used_kb = total_kb - available_kb;
    return (float)used_kb / (float)total_kb;
}

static void* admission_monitor_loop(void *arg) {
    AdmissionController *controller = (AdmissionController*) arg;
    CpuStats prev_stats = read_cpu_stats();
    
    float smoothed_cpu = 0.0f;
    bool is_first_sample = true; // Penanda sampel pertama yang bersih dari edge case 0.0f
    
    while (atomic_load(&controller->is_running)) {
        // Sampling setiap 100ms agar sangat responsif terhadap lonjakan kilat wrk
        usleep(100000); 
        
        CpuStats curr_stats = read_cpu_stats();
        float cpu_usage = 0.0f;
        
        if (calculate_cpu_percentage(&prev_stats, &curr_stats, &cpu_usage)) {
            prev_stats = curr_stats; 
            
            // Terapkan Exponential Moving Average (EMA) dengan alpha = 0.25f
            if (is_first_sample) {
                smoothed_cpu = cpu_usage;
                is_first_sample = false;
            } else {
                smoothed_cpu = (0.25f * cpu_usage) + (0.75f * smoothed_cpu);
            }
            
            // Simpan hasil yang sudah di-smoothing ke atomic variable
            atomic_store(&controller->live_cpu_usage, smoothed_cpu);
            
            bool cpu_overload = atomic_load(&controller->is_cpu_overloaded);
            
            // Evaluasi Hysteresis CPU menggunakan nilai smoothed_cpu
            if (!cpu_overload && smoothed_cpu >= controller->max_cpu_threshold) {
                atomic_store(&controller->is_cpu_overloaded, true);
            } else if (cpu_overload && smoothed_cpu <= controller->recovery_cpu_threshold) {
                atomic_store(&controller->is_cpu_overloaded, false);
            }
        }
        
        float ram_usage = get_system_ram_usage();
        atomic_store(&controller->live_ram_usage, ram_usage);
        
        bool ram_overload = atomic_load(&controller->is_ram_overloaded);
        
        // Evaluasi Hysteresis RAM menggunakan threshold dinamis
        if (!ram_overload && ram_usage >= controller->max_ram_threshold) {
            atomic_store(&controller->is_ram_overloaded, true);
        } else if (ram_overload && ram_usage <= controller->recovery_ram_threshold) {
            atomic_store(&controller->is_ram_overloaded, false);
        }
    }
    return NULL;
}

AdmissionController* core_admission_init(void) {
    AdmissionController *controller = (AdmissionController*) malloc(sizeof(AdmissionController));
    if (!controller) return NULL;
    
    controller->max_cpu_threshold = ADMISSION_MAX_CPU;
    controller->recovery_cpu_threshold = ADMISSION_RECOVERY_CPU;
    controller->max_ram_threshold = ADMISSION_MAX_RAM;
    controller->recovery_ram_threshold = ADMISSION_RECOVERY_RAM;
    
    atomic_init(&controller->live_cpu_usage, 0.0f);
    atomic_init(&controller->live_ram_usage, 0.0f);
    atomic_init(&controller->is_cpu_overloaded, false);
    atomic_init(&controller->is_ram_overloaded, false);
    atomic_init(&controller->is_running, true);
    
    int rc = pthread_create(&controller->monitor_thread, NULL, admission_monitor_loop, controller);
    if (rc != 0) {
        free(controller);
        return NULL;
    }
    
    return controller;
}

bool core_admission_evaluate(AdmissionController *controller, size_t current_queue_size) {
    if (!controller) return true;
    
    // 1. Ambil kapasitas antrean adaptif dengan fallback pengaman
    size_t adaptive_max_queue = (size_t)g_queue_capacity;
    if (adaptive_max_queue == 0) adaptive_max_queue = 256; 

    // Cek kapasitas fisik antrean (Batas keras 95%)
    if (current_queue_size >= (adaptive_max_queue * 0.95)) {
        return false; 
    }
    
    // 2. Evaluasi RAM (HARD CUTOFF - Wajib Tegas demi Mencegah OOM Killer)
    if (atomic_load(&controller->is_ram_overloaded)) {
        return false;
    }

    // 3. Dual-Factor Check: Hitung rasio kepadatan antrean tugas
    float queue_ratio = (float)current_queue_size / (float)adaptive_max_queue;

    // Ambil nilai CPU yang sudah dihaluskan dengan EMA oleh background monitor loop
    float current_cpu = atomic_load(&controller->live_cpu_usage);

    // KUNCI UTAMA DARI QA:
    // Load shedding CPU HANYA AKTIF jika CPU melewati batas (misal 92%) 
    // DAN antrean tugas juga sudah terisi lebih dari 50% (artinya worker mulai kewalahan).
    // Jika CPU 95% tapi antrean kosong/lancar -> Jangan drop! Server sedang bekerja cepat.
    if (current_cpu >= controller->max_cpu_threshold && queue_ratio > 0.50f) {
        
        float denom = (1.0f - controller->max_cpu_threshold);
        if (denom <= 0.001f) denom = 0.001f;
        
        // Severity proporsional yang juga dikalikan dengan kepadatan antrean
        float severity = ((current_cpu - controller->max_cpu_threshold) / denom) * queue_ratio;
        if (severity > 1.0f) severity = 1.0f;

        static __thread unsigned int thread_seed = 0;
        if (thread_seed == 0) {
            thread_seed = (unsigned int)(pthread_self() ^ (unsigned long)time(NULL));
        }
        
        float random_roll = (float)rand_r(&thread_seed) / (float)RAND_MAX;

        if (random_roll < severity) {
            return false; // Soft load shedding probabilistik yang cerdas
        }
    }
    
    return true;
}

void core_admission_destroy(AdmissionController *controller) {
    if (!controller) return;
    
    atomic_store(&controller->is_running, false);
    pthread_join(controller->monitor_thread, NULL);
    free(controller);
}