#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

// Header fungsi helper
static void* log_thread_routine(void* arg);
static void enqueue_log(LogType type, const char *format, va_list args);

// 1. Inisialisasi Global Log Queue
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
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char log_filename[256];
        char date_str[15];
        strftime(date_str, sizeof(date_str), "%Y-%m-%d", t);

        if (current_entry.type == LOG_TYPE_ERROR) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_error.log", LOG_DIR, date_str);
        } else {
            snprintf(log_filename, sizeof(log_filename), "%s%s_system.log", LOG_DIR, date_str);
        }

        FILE *f = fopen(log_filename, "a");
        if (f) {
            char ts[25];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
            fprintf(f, "[%s] [%s] %s\n", ts, 
                    (current_entry.type == LOG_TYPE_ERROR ? "ERROR" : "INFO"), 
                    current_entry.text);
            fclose(f);
        }
    }
    return NULL;
}

void enqueue_log(LogType type, const char *format, va_list args) {
    pthread_mutex_lock(&global_log_queue.mutex);
    
    if (global_log_queue.count < MAX_LOG_QUEUE) {
        int tail = global_log_queue.tail;
        
        // Simpan pesan dan tipenya
        vsnprintf(global_log_queue.entries[tail].text, MAX_LOG_MESSAGE, format, args);
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