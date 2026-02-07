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
    // --- STEP 1: Deteksi Hardware (Logika Lama yang Stabil) ---
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit rl;
    struct sysinfo si;
    getrlimit(RLIMIT_NOFILE, &rl);
    sysinfo(&si);

    // Hitung plafon berdasarkan 10% RAM (Sangat aman untuk i3 6GB)
    int buf_size = (config.request_buffer_size > 0) ? config.request_buffer_size : 4096;
    unsigned long free_mem_bytes = (unsigned long)si.freeram * si.mem_unit;
    int ram_based_max = (int)((free_mem_bytes * 0.10) / buf_size);
    
    // Tentukan Global Max Worker (Inilah yang bikin .html kencang)
    // Angka 10.000 menganur sistem C10K Problem (Ten Thousand Concurrent Connections).
    g_worker_max = (ram_based_max > 10000) ? 10000 : (ram_based_max < 64 ? 64 : ram_based_max);
    
    // --- STEP 2: Ambil Konfigurasi PHP ---
    PHPConfig php = fetch_php_fpm_config();
    
    // --- STEP 3: Pembagian Quota (Logika Baru) ---
    // Kita tetap hormati max_children PHP agar PHP-FPM tidak overload
    fcgi_pool.php_quota    = php.max_children; 
    
    // Sisanya kita bagi untuk Rust dan Python secara proporsional
    // atau kasih nilai sisa dari plafon worker kita
    int sisa_jatah = g_worker_max - php.max_children;
    if (sisa_jatah < 40) sisa_jatah = 40; // Safety net

    fcgi_pool.rust_quota   = (int)(sisa_jatah * 0.4); // Rust 40% dari sisanya PHP
    fcgi_pool.python_quota = (int)(sisa_jatah * 0.6); // Python 60% dari sisanya PHP
    fcgi_pool.pool_size    = fcgi_pool.php_quota + fcgi_pool.rust_quota + fcgi_pool.python_quota;

    // --- STEP 4: Sinkronisasi Variabel Core ---
    g_fcgi_pool_size = fcgi_pool.pool_size;
    g_worker_min     = (int)num_cores * 4;
    
    // Kembalikan Batch Size ke "Power Mode"
    // angka 1024 sangat dipengaruhi oleh arsitektur Kernel Linux dan efisiensi L1/L2 Cache CPU
    g_event_batch_size = (g_worker_max > 1024) ? 1024 : g_worker_max;

    // Kembalikan Antrean ke "Lega Mode" (Logika Lama)
    g_queue_capacity = (int)((rl.rlim_cur - g_worker_max) * 0.5);
    if (g_queue_capacity < 2000)  g_queue_capacity = 2000;
    if (g_queue_capacity > 65535) g_queue_capacity = 65535;

    write_log("HALMOS HYBRID ADAPTIVE ACTIVE");
    write_log("[CORE] Workers: %d | Batch: %d | Queue: %d", g_worker_max, g_event_batch_size, g_queue_capacity);
    write_log("[FCGI] PHP Quota: %d (Sync with FPM) | Total Pool: %d", fcgi_pool.php_quota, g_fcgi_pool_size);

    // Advise

    // --- STEP 6: ADMIN ADVISOR (LOGIKA AUDIT) ---
    // 1. Audit RAM vs PHP-FPM
    // Hitung angka saran (Misal: 50% dari kapasitas RAM aman)
    // Pakai logika kamu yang asli
    int recommended_children = (int)(ram_based_max * 0.5);
    
    // --- TAMBAHKAN SANITY CHECK DISINI ---
    // Walaupun RAM sanggup 8000, tapi CPU i3 punya batas lelah.
    // Kita batasi saran maksimal di 512 agar admin tidak "bunuh diri".
    if (recommended_children > 512) recommended_children = 512; 
    if (recommended_children < 20)  recommended_children = 20;

    // 1. Audit RAM vs PHP-FPM (Tetap pakai variabel asli kamu)
    if (php.max_children > ram_based_max) {
        write_log("ADVICE: [CRITICAL] php-fpm.max_children (%d) exceeds safe RAM limit (%d)!", 
                  php.max_children, ram_based_max);
        write_log("ADVICE: -> Decrease max_children to %d to prevent server hang/OOM issues.", 
                  recommended_children);
    } 
    else if (php.max_children < (ram_based_max * 0.1)) {
        write_log("ADVICE: [PERFORMANCE] php-fpm.max_children is too low (%d).", php.max_children);
        write_log("ADVICE: -> For optimal performance, consider increasing max_children to %d.", 
                  recommended_children);
    } 

    // 2. Audit ulimit (Sering jadi penyebab server 'tuli' terhadap request baru)
    if ((long)rl.rlim_cur < (long)(g_worker_max + 100)) {
        write_log("ADVICE: [SYSTEM] ulimit -n (%ld) is too low! Target worker is %d.", 
                  (long)rl.rlim_cur, g_worker_max);
        write_log("ADVICE: -> Run 'ulimit -n %d' before starting Halmos to avoid connection drops.", 
                  g_worker_max + 2000);
    } 
}

