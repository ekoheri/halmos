#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

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

void write_log(const char *format, ...) {
    char temp_msg[MAX_LOG_MESSAGE];
    
    // Format pesan variadic
    va_list args;
    va_start(args, format);
    vsnprintf(temp_msg, sizeof(temp_msg), format, args);
    va_end(args);

    pthread_mutex_lock(&global_log_queue.mutex);
    
    // Jika antrean belum penuh, masukkan pesan
    if (global_log_queue.count < MAX_LOG_QUEUE) {
        //strncpy(global_log_queue.messages[global_log_queue.tail], temp_msg, MAX_LOG_MESSAGE - 1);
        snprintf(global_log_queue.messages[global_log_queue.tail], MAX_LOG_MESSAGE, "%s", temp_msg);
        global_log_queue.messages[global_log_queue.tail][MAX_LOG_MESSAGE - 1] = '\0';
        
        global_log_queue.tail = (global_log_queue.tail + 1) % MAX_LOG_QUEUE;
        global_log_queue.count++;
        
        // Bangunkan thread logger
        pthread_cond_signal(&global_log_queue.cond);
    }
    
    pthread_mutex_unlock(&global_log_queue.mutex);
}

/**
 * LOGGER THREAD (CONSUMER):
 * Berjalan di background, bertugas memindahkan log dari RAM ke Disk.
 */
void* log_thread_routine(void* arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&global_log_queue.mutex);
        
        // Tunggu selama antrean kosong DAN server masih disuruh jalan
        while (global_log_queue.count == 0 && log_keep_running) {
            pthread_cond_wait(&global_log_queue.cond, &global_log_queue.mutex);
        }

        // Cek kondisi keluar: Berhenti hanya jika flag false DAN antrean sudah ludes
        if (!log_keep_running && global_log_queue.count == 0) {
            pthread_mutex_unlock(&global_log_queue.mutex);
            break; 
        }

        // Ambil data dari antrean (Circular Buffer)
        char current_msg[MAX_LOG_MESSAGE];
        strncpy(current_msg, global_log_queue.messages[global_log_queue.head], MAX_LOG_MESSAGE - 1);
        current_msg[MAX_LOG_MESSAGE - 1] = '\0';
        
        global_log_queue.head = (global_log_queue.head + 1) % MAX_LOG_QUEUE;
        global_log_queue.count--;
        
        // BUKA KUNCI SEBELUM DISK I/O (Penting untuk performa!)
        pthread_mutex_unlock(&global_log_queue.mutex);

        // --- PROSES PENULISAN DISK ---
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char log_filename[128];
        snprintf(log_filename, sizeof(log_filename), "%s%04d-%02d-%02d.log",
                 LOG_DIR, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

        FILE *f = fopen(log_filename, "a");
        if (f) {
            char ts[25];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
            fprintf(f, "[%s] %s\n", ts, current_msg);
            fclose(f);
        }
    }
    
    return NULL;
}

void start_thread_logger() {
    pthread_t log_tid;
    
    if (pthread_create(&log_tid, NULL, log_thread_routine, NULL) != 0) {
        // Pakai fprintf atau tulis ke stderr karena logger sendiri belum siap
        fprintf(stderr, "FATAL: Gagal menjalankan thread logger!\n");
    }

    // Detach supaya resource thread otomatis bebas saat thread selesai
    pthread_detach(log_tid);
}