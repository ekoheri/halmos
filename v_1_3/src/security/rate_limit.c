#include "rate_limit.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static RateEntry hash_table[HASH_TABLE_SIZE];
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

// Algoritma DJB2 Hash - Sangat cepat untuk string (IP Address)
static unsigned long hash_ip(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash % HASH_TABLE_SIZE;
}

bool is_request_allowed(const char *client_ip, int limit_per_sec) {
    if (client_ip == NULL || strlen(client_ip) == 0) return true;

    unsigned long index = hash_ip(client_ip);
    time_t now = time(NULL);

    pthread_mutex_lock(&rate_limit_mutex);

    // Linear Probing untuk menangani Collision (Tabrakan Hash)
    int i = 0;
    while (i < HASH_TABLE_SIZE) {
        unsigned long current_idx = (index + i) % HASH_TABLE_SIZE;
        
        // 1. Jika Slot Kosong -> IP Baru
        if (hash_table[current_idx].ip[0] == '\0') {
            strncpy(hash_table[current_idx].ip, client_ip, 45);
            hash_table[current_idx].count = 1;
            hash_table[current_idx].window_start = now;
            pthread_mutex_unlock(&rate_limit_mutex);
            return true;
        }

        // 2. Jika IP Ditemukan
        if (strcmp(hash_table[current_idx].ip, client_ip) == 0) {
            // Cek apakah sudah beda detik
            if (now > hash_table[current_idx].window_start) {
                hash_table[current_idx].count = 1;
                hash_table[current_idx].window_start = now;
                pthread_mutex_unlock(&rate_limit_mutex);
                return true;
            }

            // Cek Limit
            if (hash_table[current_idx].count < limit_per_sec) {
                hash_table[current_idx].count++;
                pthread_mutex_unlock(&rate_limit_mutex);
                return true;
            } else {
                pthread_mutex_unlock(&rate_limit_mutex);
                return false; // RATE LIMIT EXCEEDED
            }
        }

        i++; // Lanjut cari slot berikutnya kalau tabrakan
    }

    pthread_mutex_unlock(&rate_limit_mutex);
    return true; 
}

void reset_rate_limits() {
    pthread_mutex_lock(&rate_limit_mutex);
    
    // Langsung sikat semua data di table (Memset ke nol)
    // Ini cara paling cepat kalau mau reset total
    memset(hash_table, 0, sizeof(hash_table));
    
    pthread_mutex_unlock(&rate_limit_mutex);
    // printf("[SYSTEM] Rate limit table has been cleared.\n");
}

void clean_old_rate_limits() {
    pthread_mutex_lock(&rate_limit_mutex);
    
    time_t now = time(NULL);
    int cleared = 0;

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        // Jika slot ada isinya dan sudah lebih dari 10 detik tidak aktif
        if (hash_table[i].ip[0] != '\0' && (now - hash_table[i].window_start > 10)) {
            memset(&hash_table[i], 0, sizeof(RateEntry));
            cleared++;
        }
    }
    
    pthread_mutex_unlock(&rate_limit_mutex);
    // if(cleared > 0) printf("[SYSTEM] Janitor cleared %d inactive IPs\n", cleared);
}