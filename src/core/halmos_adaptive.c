#include "halmos_adaptive.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include "halmos_config.h"
#include "halmos_fcgi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <ctype.h>

// Definisikan variabelnya di sini agar dialokasikan memori
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

PHPConfig fetch_php_fpm_config() {
    PHPConfig cfg = {50, 511, "dynamic"}; 

    // Sekarang pakai path dari config Halmos, bukan hardcoded lagi!
    if (strlen(config.php_fpm_config_path) == 0) {
        write_log_error("[WARN] php_fpm_config_path is empty");
        return cfg;
    }

    FILE *fp = fopen(config.php_fpm_config_path, "r");
    if (!fp) {
        write_log_error("[ERROR] Cant't open file PHP-FPM config in: %s", config.php_fpm_config_path);
        return cfg;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // 1. Bersihkan spasi di awal baris (indentasi)
        char *ptr = line;
        while (*ptr == ' ' || *ptr == '\t') ptr++;

        // 2. Abaikan komentar atau baris kosong
        if (*ptr == ';' || *ptr == '#' || *ptr == '\n' || *ptr == '\0') continue;

        // 3. Cari kunci pm.max_children
        if (strstr(ptr, "pm.max_children")) {
            char *eq = strchr(ptr, '=');
            if (eq) cfg.max_children = atoi(eq + 1);
        }
        
        // 4. Cari kunci listen.backlog
        else if (strstr(ptr, "listen.backlog")) {
            char *eq = strchr(ptr, '=');
            if (eq) cfg.backlog = atoi(eq + 1);
        }
        
        // 5. Cari kunci pm (mode)
        else if (strstr(ptr, "pm =") || strstr(ptr, "pm=")) {
            char *eq = strchr(ptr, '=');
            if (eq) {
                // Lewati spasi setelah '=' jika ada
                char *val = eq + 1;
                while (*val == ' ' || *val == '\t') val++;
                sscanf(val, "%s", cfg.mode);
            }
        }
    }
    fclose(fp);
    return cfg;
}

void halmos_adaptive_init_all(void) {
    // --- STEP 1: Deteksi Hardware ---
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit rl;
    struct sysinfo si;
    getrlimit(RLIMIT_NOFILE, &rl);
    sysinfo(&si);

    // --- [ADVISE GEMINI]: Pengali 64 adalah angka "Aman" buat i3 biar gak Freeze ---
    int cpu_based_max = (int)(num_cores * 64); 

    // --- [ADVISE GEMINI]: Pakai Total RAM, ambil jatah 10% buat Safety Margin ---
    int buf_size = (config.request_buffer_size > 0) ? config.request_buffer_size : 4096;
    unsigned long total_ram_bytes = (unsigned long)si.totalram * si.mem_unit;
    int ram_based_max = (int)((total_ram_bytes * 0.10) / buf_size);

    // --- [ADVISE GEMINI]: Logika Anti-Sesat (Gak asal 10.000 lagi) ---
    // Ambil nilai terkecil antara RAM vs CPU.
    int recommended_val = (cpu_based_max < ram_based_max) ? cpu_based_max : ram_based_max;
    
    // Plafon maksimal buat mesin kelas i3/Laptop biar OS gak stuck
    if (recommended_val > 1024) recommended_val = 1024;
    if (recommended_val < 32)   recommended_val = 32;

    // --- [ADVISE GEMINI]: Sinkronisasi Global Worker ---
    // g_worker_max sekarang JUJUR sesuai hardware, bukan angka ghaib!
    g_worker_max = recommended_val;
    g_worker_min = (int)num_cores * 4;

    // --- STEP 2: Ambil Konfigurasi PHP ---
    PHPConfig php = fetch_php_fpm_config();
    
    // --- STEP 3: Pembagian Quota Hybrid ---
    fcgi_pool.php_quota = php.max_children; 
    
    // Sisa jatah buat Rust & Python (Biar adil bagi-bagi slot)
    int sisa_jatah = g_worker_max - php.max_children;
    if (sisa_jatah < 40) sisa_jatah = 40; 

    fcgi_pool.rust_quota   = (int)(sisa_jatah * 0.4); 
    fcgi_pool.python_quota = (int)(sisa_jatah * 0.6); 
    fcgi_pool.pool_size    = fcgi_pool.php_quota + fcgi_pool.rust_quota + fcgi_pool.python_quota;
    g_fcgi_pool_size       = fcgi_pool.pool_size;

    // --- STEP 4: Optimization ---
    g_event_batch_size = (g_worker_max > 1024) ? 1024 : g_worker_max;

    // [ADVISE GEMINI]: Ulimit harus g_worker_max + Buffer Antrean
    int smart_ulimit = g_worker_max + 2000; 

    g_queue_capacity = (int)((rl.rlim_cur - g_worker_max) * 0.5);
    if (g_queue_capacity < 2000)  g_queue_capacity = 2000;

    // --- STEP 5: LOGGING ---
    write_log("HALMOS HYBRID ADAPTIVE ACTIVE");
    write_log("[CORE] Workers: %d | Batch: %d | Queue: %d", g_worker_max, g_event_batch_size, g_queue_capacity);
    write_log("[FCGI] PHP Quota: %d (Sync with FPM) | Total Pool: %d", fcgi_pool.php_quota, g_fcgi_pool_size);

    // --- [ADVISE GEMINI]: Logika Audit Cerdas (Bodyguard Mode) ---
    
    // 1. Audit ulimit
    if ((long)rl.rlim_cur < (long)smart_ulimit) {
        write_log("ADVICE: [SYSTEM] ulimit -n (%ld) is too low for stability.", (long)rl.rlim_cur);
        write_log("ADVICE: -> Run 'ulimit -n %d' for optimal stability on this i3.", smart_ulimit);
    }

    // 2. Audit PHP-FPM: Jika settingan user lebay/kegedean
    if (php.max_children > g_worker_max) {
        write_log("ADVICE: [CRITICAL] php-fpm.max_children (%d) is too high for your CPU/RAM!", php.max_children);
        write_log("ADVICE: -> Decrease to %d to prevent server freeze.", g_worker_max);
    } else if (php.max_children < (g_worker_max / 2)) {
        write_log("ADVICE: [PERFORMANCE] php-fpm.max_children (%d) can be increased.", php.max_children);
        write_log("ADVICE: -> Safe limit for your hardware: %d.", g_worker_max);
    }
}
