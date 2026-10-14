#ifndef HALMOS_LOG_H
#define HALMOS_LOG_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#define LOG_DIR "/var/log/halmos/"
#define MAX_LOG_QUEUE 1024
#define MAX_LOG_MESSAGE 512

// --- 1. Struktur Telemetry (Wadah Angka) ---
typedef struct {
    _Atomic unsigned long total_requests;    
    _Atomic unsigned int  active_connections; 
    _Atomic size_t        mem_usage_kb;      
    _Atomic double        last_latency_ms;   
} LogTelemetry;

// Enum untuk Event Halmos Metrics
typedef enum {
    HALMOS_EVENT_INIT = 1,
    METRIC_EVENT_UPSCALE,
    METRIC_EVENT_DOWNSCALE,
    HALMOS_EVENT_QUEUE_FULL,
    HALMOS_EVENT_CUSTOM
} LogMetricEvent;

// Tipe Log
typedef enum {
    LOG_TYPE_SYSTEM,
    LOG_TYPE_ERROR,
    LOG_TYPE_ACCESS,
    LOG_TYPE_TELEMETRY,
    LOG_TYPE_METRICS // BARU: Untuk format CSV khusus metrik Halmos
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

// Deklarasi global agar bisa diakses file lain
extern LogTelemetry global_telemetry;

// Deklarasi fungsi-fungsi log utama
void write_log(const char *format, ...);
void write_log_error(const char *format, ...); 
void write_log_access(const char *protocol, 
    const char *client_ip, 
    const char *method, 
    const char *uri, 
    int status, long bytes_sent);
void write_log_telemetry();

// Deklarasi fungsi Halmos Metrics (Asinkron via Queue)
void metrics_log_event(LogMetricEvent event, int delta, uint32_t q_len, uint32_t workers, uint32_t active);
void metrics_log_periodic(uint32_t q_len, uint32_t q_cap, uint32_t workers, uint32_t active, uint64_t avg_wait_us);
// Tambahkan deklarasi fungsi ini
void metrics_log_task_execution(uint32_t q_len, uint32_t workers, uint32_t active, uint64_t execution_time_us, int bound_type);

void start_thread_logger();
void stop_thread_logger();
void update_mem_usage();

double hitung_durasi(struct timespec start, struct timespec end);

#endif // HALMOS_LOG_H