#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/resource.h>

// Header fungsi helper
static void* log_thread_routine(void* arg);
static void enqueue_log(LogType type, const char *format, va_list args);

// 1. Inisialisasi Telemetry Global
HalmosTelemetry global_telemetry = {
    .total_requests = 0,
    .active_connections = 0,
    .mem_usage_kb = 0,
    .last_latency_ms = 0.0
};

// 2. Inisialisasi Global Log Queue
LogQueue global_log_queue = {
    .head = 0, 
    .tail = 0, 
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

// 2. Flag untuk kontrol Graceful Shutdown
volatile bool log_keep_running = true;

// 3. Deklarasikan log_tid di sini agar bisa diakses semua fungsi dalam file ini
static pthread_t log_tid; 

void write_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    enqueue_log(LOG_TYPE_SYSTEM, format, args);
    va_end(args);
}

void write_log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    enqueue_log(LOG_TYPE_ERROR, format, args);
    va_end(args);
}

void write_log_telemetry() {
    // 1. UPDATE RAM: Tanya ke Kernel dulu sebelum lapor!
    update_mem_usage();

    char meta_buffer[MAX_LOG_MESSAGE];
    
    // 2. AMBIL WAKTU PRESISI (Milidetik)
    struct timespec ts_now;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    struct tm *t = localtime(&ts_now.tv_sec);
    long ms = ts_now.tv_nsec / 1000000;

    // 3. FORMAT TIMESTAMP (YYYY-MM-DD HH:MM:SS.mmm)
    char ts_full[32];
    strftime(ts_full, sizeof(ts_full), "%Y-%m-%d %H:%M:%S", t);
    snprintf(ts_full + strlen(ts_full), sizeof(ts_full) - strlen(ts_full), ".%03ld", ms);

    // 4. BUNGKUS KE JSON
    snprintf(meta_buffer, MAX_LOG_MESSAGE, 
             "{\"ts\":\"%s\",\"type\":\"metrics\",\"req\":%lu,\"conn\":%u,\"ram_kb\":%zu,\"lat_ms\":%.3f}", 
             ts_full,
             global_telemetry.total_requests,
             global_telemetry.active_connections,
             global_telemetry.mem_usage_kb,
             global_telemetry.last_latency_ms);

    // 5. KIRIM KE ANTREAN
    enqueue_log(LOG_TYPE_METRICS, meta_buffer, (va_list){0});
}

void start_thread_logger() {
    /*pthread_t log_tid;
    
    if (pthread_create(&log_tid, NULL, log_thread_routine, NULL) != 0) {
        // Pakai fprintf atau tulis ke stderr karena logger sendiri belum siap
        fprintf(stderr, "FATAL: Gagal menjalankan thread logger!\n");
    }

    // Detach supaya resource thread otomatis bebas saat thread selesai
    pthread_detach(log_tid);
    */
    if (pthread_create(&log_tid, NULL, log_thread_routine, NULL) != 0) {
        fprintf(stderr, "FATAL: Gagal menjalankan thread logger!\n");
    }
}


// Fungsi Helper

/**
 * LOGGER THREAD (CONSUMER):
 * Berjalan di background, bertugas memindahkan log dari RAM ke Disk.
 */
void* log_thread_routine(void* arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&global_log_queue.mutex);
        
        // Tunggu jika kosong DAN masih berjalan
        while (global_log_queue.count == 0 && log_keep_running) {
            pthread_cond_wait(&global_log_queue.cond, &global_log_queue.mutex);
        }

        // KUNCI: Jika disuruh berhenti tapi masih ada antrean, lanjut dulu!
        if (!log_keep_running && global_log_queue.count == 0) {
            pthread_mutex_unlock(&global_log_queue.mutex);
            break; 
        }

        LogEntry current_entry = global_log_queue.entries[global_log_queue.head];
        global_log_queue.head = (global_log_queue.head + 1) % MAX_LOG_QUEUE;
        global_log_queue.count--;
        
        pthread_mutex_unlock(&global_log_queue.mutex);

        // --- Proses Tulis File ---
        // --- AMBIL WAKTU PRESISI TINGGI (CLOCK_REALTIME) ---
        struct timespec ts_now;
        clock_gettime(CLOCK_REALTIME, &ts_now);
        
        struct tm *t = localtime(&ts_now.tv_sec);
        long milliseconds = ts_now.tv_nsec / 1000000; // Nanodetik ke Milidetik

        char log_filename[256];
        char date_str[15];
        char time_str[32];

        // Format tanggal untuk nama file
        strftime(date_str, sizeof(date_str), "%Y-%m-%d", t);
        
        // Format waktu: Jam:Menit:Detik.Milidetik (Contoh: 13:23:45.002)
        strftime(time_str, sizeof(time_str), "%H:%M:%S", t);
        snprintf(time_str + strlen(time_str), sizeof(time_str) - strlen(time_str), ".%03ld", milliseconds);

        // Tentukan Nama File berdasarkan Type
        if (current_entry.type == LOG_TYPE_ERROR) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_error.log", LOG_DIR, date_str);
        } else if (current_entry.type == LOG_TYPE_METRICS) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_telemetry.log", LOG_DIR, date_str);
        } else {
            snprintf(log_filename, sizeof(log_filename), "%s%s_system.log", LOG_DIR, date_str);
        }

        FILE *f = fopen(log_filename, "a");
        if (f) {
            if (current_entry.type == LOG_TYPE_METRICS) {
                // Untuk metrik, kita print mentah-mentah JSON-nya per baris
                // Kita tambahkan timestamp di dalam JSON agar lebih keren
                fprintf(f, "%s\n", current_entry.text); 
            } else {
                // Untuk log biasa (System/Error), tetap pakai format lama yang manusiawi
                const char* label = (current_entry.type == LOG_TYPE_ERROR) ? "ERROR" : "INFO";
                fprintf(f, "[%s] [%s] %s\n", time_str, label, current_entry.text);
            }
            fclose(f);
        }
    }
    return NULL;
}

void update_mem_usage() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        // Di Linux, ru_maxrss hasilnya dalam Kilobytes (KB)
        global_telemetry.mem_usage_kb = (size_t)usage.ru_maxrss;
    }
}

void enqueue_log(LogType type, const char *format, va_list args) {
    pthread_mutex_lock(&global_log_queue.mutex);
    
    if (global_log_queue.count < MAX_LOG_QUEUE) {
        int tail = global_log_queue.tail;
        
        // Simpan pesan dan tipenya
        // FIX 3: Cek jika args valid (untuk write_log) atau NULL (untuk telemetry)
        if (format) {
            if (type == LOG_TYPE_METRICS) {
                // Ganti strncpy dengan snprintf untuk menghilangkan warning
                // Ini menjamin string selalu diakhiri dengan '\0'
                snprintf(global_log_queue.entries[tail].text, MAX_LOG_MESSAGE, "%s", format);
            } else {
                // Untuk log biasa tetap pakai vsnprintf
                vsnprintf(global_log_queue.entries[tail].text, MAX_LOG_MESSAGE, format, args);
            }
        }
        global_log_queue.entries[tail].type = type;
        
        global_log_queue.tail = (tail + 1) % MAX_LOG_QUEUE;
        global_log_queue.count++;
        
        pthread_cond_signal(&global_log_queue.cond);
    }
    
    pthread_mutex_unlock(&global_log_queue.mutex);
}

void stop_thread_logger() {
    pthread_mutex_lock(&global_log_queue.mutex);
    log_keep_running = false; 
    pthread_cond_signal(&global_log_queue.cond); 
    pthread_mutex_unlock(&global_log_queue.mutex);

    // Sekarang compiler nggak akan marah lagi karena log_tid sudah dikenal
    pthread_join(log_tid, NULL);
    
    //fprintf(stderr, "[HALMOS] Logger thread joined. Goodbye.\n");
}

//helper
double hitung_durasi(struct timespec start, struct timespec end) {
    double s = (double)end.tv_sec - (double)start.tv_sec;
    double ns = (double)end.tv_nsec - (double)start.tv_nsec;
    return (s * 1000.0) + (ns / 1000000.0); // Hasil dalam milidetik (ms)
}