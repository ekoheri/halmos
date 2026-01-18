#ifndef LOG_H
#define LOG_H

#include <pthread.h>

#define LOG_DIR "/var/log/halmos/"
#define MAX_LOG_QUEUE 1024
#define MAX_LOG_MESSAGE 512

// Struktur Antrean Log (Circular Buffer)
typedef struct {
    char messages[MAX_LOG_QUEUE][MAX_LOG_MESSAGE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} LogQueue;

// Deklarasi fungsi-fungsi log
void write_log(const char *format, ...);
void* log_thread_routine(void* arg);

#endif // LOG_H