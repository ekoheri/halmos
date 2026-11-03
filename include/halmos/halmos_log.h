#ifndef HALMOS_LOG_H
#define HALMOS_LOG_H

#include "halmos_errors.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#define LOG_DIR "/var/log/halmos/"
#define MAX_LOG_QUEUE 1024
#define MAX_LOG_MESSAGE 512

// Tipe Log (Hanya menyisakan system, error, warning, dan access)
typedef enum {
    LOG_TYPE_SYSTEM,
    LOG_TYPE_ERROR,
    LOG_TYPE_WARNING,
    LOG_TYPE_ACCESS
} LogType;

// Struktur pesan yang disimpan di queue
typedef struct {
    char text[MAX_LOG_MESSAGE];
    LogType type; 
    time_t timestamp; 
} LogEntry;

// Struktur Antrean Log (Circular Buffer)
typedef struct {
    LogEntry entries[MAX_LOG_QUEUE]; 
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} LogQueue;

// Deklarasi fungsi-fungsi log utama
void write_log(const char *format, ...);
void write_log_error(const char *format, ...); 
void write_log_error_code(HalmosErrorCode code, ...);
void write_log_warn_code(HalmosErrorCode code, ...);
void write_log_access(const char *protocol, 
    const char *client_ip, 
    const char *method, 
    const char *uri, 
    int status, long bytes_sent);

void start_thread_logger();
void stop_thread_logger();

double hitung_durasi(struct timespec start, struct timespec end);

#endif // HALMOS_LOG_H