#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define MAX_TRACKED_IPS 5000
// Gunakan ukuran bilangan prima untuk performa Hash Table yang lebih baik
#define HASH_TABLE_SIZE 10007

typedef struct {
    char ip[45];
    int count;
    time_t window_start;
} RateEntry;

// Fungsi Utama
bool is_request_allowed(const char *client_ip, int limit_per_sec);

// Cleanup berkala untuk menghapus IP yang sudah tidak aktif (opsional)
void reset_rate_limits();

void reset_rate_limits();

void clean_old_rate_limits(); 

#endif