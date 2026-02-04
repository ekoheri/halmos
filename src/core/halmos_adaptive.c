#include "halmos_adaptive.h"
#include "halmos_global.h"
#include "halmos_log.h"

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>

// Definisikan variabelnya di sini agar dialokasikan memori
int g_event_batch_size = 0;
int g_fcgi_pool_size = 0;
int g_worker_max = 0;
int g_worker_min = 0;
int g_queue_capacity = 0;

void halmos_adaptive_init_all(void) {
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    struct rlimit rl;
    struct sysinfo si;
    
    // --- PILAR 1: Batasan Izin (FD) ---
    // Menggunakan logika asli Boss: 10% dari limit yang ada
    int fd_based_max = 1000;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        fd_based_max = (int)(rl.rlim_cur / 10);
    }

    // --- PILAR 2: Batasan Fisik (RAM) ---
    // Menggunakan logika asli Boss: 10% dari freeram / buffer_size
    int ram_based_max = 1000;
    if (sysinfo(&si) == 0) {
        int buf_size = config.request_buffer_size > 0 ? config.request_buffer_size : 4096;
        unsigned long free_mem_bytes = (unsigned long)si.freeram * si.mem_unit;
        ram_based_max = (int)((free_mem_bytes * 0.10) / buf_size);
    }

    // --- EKSEKUSI: Minimum Resource Bottleneck ---
    int dynamic_thread_max = (fd_based_max < ram_based_max) ? fd_based_max : ram_based_max;

    // Guardrail asli Boss
    if (dynamic_thread_max > 10000) dynamic_thread_max = 10000;
    if (dynamic_thread_max < 16) dynamic_thread_max = 16;

    // --- SINKRONISASI KE VARIABEL GLOBAL ---
    g_worker_max     = dynamic_thread_max;
    g_fcgi_pool_size = dynamic_thread_max; // Biar pool FCGI sinkron dengan plafon thread
    g_worker_min     = (int)num_cores * 4;
    
    if (g_worker_min > g_worker_max) g_worker_min = g_worker_max;

    // --- STRATEGI ANTREAN ADAPTIF (Asli Boss) ---
    g_queue_capacity = (int)((rl.rlim_cur - g_worker_max) * 0.5);
    if (g_queue_capacity < 1000)  g_queue_capacity = 1000;
    if (g_queue_capacity > 65535) g_queue_capacity = 65535;

    // Batch size untuk epoll disesuaikan dengan beban minimal
    g_event_batch_size = (g_worker_max > 1024) ? 1024 : g_worker_max;

    write_log("HALMOS SAVAGE SERVER IS RUNNING");
    write_log("[ADAPTIVE] Worker: %d-%d | Queue: %d | FCGI: %d | Batch: %d", 
              g_worker_min, g_worker_max, g_queue_capacity, g_fcgi_pool_size, g_event_batch_size);
}