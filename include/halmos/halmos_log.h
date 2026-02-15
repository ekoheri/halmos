#ifndef HALMOS_LOG_H
#define HALMOS_LOG_H

#include <pthread.h>

#define LOG_DIR "/var/log/halmos/"
#define MAX_LOG_QUEUE 1024
#define MAX_LOG_MESSAGE 512

// --- 1. Struktur Telemetry (Wadah Angka) ---
typedef struct {
    unsigned long total_requests;    // Counter total request
    unsigned int  active_connections; // Koneksi yang sedang berjalan
    size_t        mem_usage_kb;      // Pemakaian RAM (RSS)
    double        last_latency_ms;   // Durasi proses terakhir
} HalmosTelemetry;

// Tipe Log
typedef enum {
    LOG_TYPE_SYSTEM,
    LOG_TYPE_ERROR,
    LOG_TYPE_METRICS // Tambahkan tipe baru untuk Telemetry
} LogType;

// Struktur pesan yang disimpan di queue
typedef struct {
    char text[MAX_LOG_MESSAGE];
    LogType type; // Menyimpan informasi tipe log
    time_t timestamp; // Tambahkan timestamp agar pencatatan waktu akurat
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

// Deklarasi global agar bisa diintip file lain
extern HalmosTelemetry global_telemetry;

// Deklarasi fungsi-fungsi log
void write_log(const char *format, ...);
void write_log_error(const char *format, ...); 
void write_log_telemetry();

void start_thread_logger();
void stop_thread_logger();
void update_mem_usage();

double hitung_durasi(struct timespec start, struct timespec end);

#endif // LOG_H