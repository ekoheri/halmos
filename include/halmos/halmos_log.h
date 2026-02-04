#ifndef HALMOS_LOG_H
#define HALMOS_LOG_H

#include <pthread.h>

#define LOG_DIR "/var/log/halmos/"
#define MAX_LOG_QUEUE 1024
#define MAX_LOG_MESSAGE 512

// Tipe Log
typedef enum {
    LOG_TYPE_SYSTEM,
    LOG_TYPE_ERROR
} LogType;

// Struktur pesan yang disimpan di queue
typedef struct {
    char text[MAX_LOG_MESSAGE];
    LogType type; // Menyimpan informasi tipe log
} LogEntry;

// Struktur Antrean Log (Circular Buffer)
typedef struct {
    // char messages[MAX_LOG_QUEUE][MAX_LOG_MESSAGE];
    LogEntry entries[MAX_LOG_QUEUE]; // Gunakan struct LogEntry
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} LogQueue;

// Deklarasi fungsi-fungsi log
void write_log(const char *format, ...);
void write_log_error(const char *format, ...); // Fungsi baru
void start_thread_logger();
void stop_thread_logger();

#endif // LOG_H