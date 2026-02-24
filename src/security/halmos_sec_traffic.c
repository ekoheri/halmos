#include "halmos_sec_traffic.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>  // Untuk setsockopt, SOL_SOCKET, SO_KEEPALIVE, SO_LINGER
#include <netinet/in.h>  // Untuk IPPROTO_TCP
#include <netinet/tcp.h> // Untuk TCP_NODELAY
#include <unistd.h>      // Untuk sleep()
#include <time.h>        // Untuk struct timeval (jika belum ada)

#include <openssl/ssl.h>
#include <stdlib.h>

static RateEntry hash_table[HASH_TABLE_SIZE];
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned long hash_ip(const char *str);

static void reset_rate_limits();

static void clean_old_rate_limits();

static void* janitor_thread(void* arg);

// Fungsi public nanti biasanya di http_manager
// Setelah parser, sebelum response
bool sec_traffic_is_request_allowed(const char *client_ip, int limit_per_sec) {
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

            if (hash_table[current_idx].count < limit_per_sec) {
                hash_table[current_idx].count++;
                pthread_mutex_unlock(&rate_limit_mutex);
                return true;
            } else {
                // LOGIKA CERDAS: Hanya tulis log jika ini request pertama yang melampaui limit
                // Agar tidak banjir log (Log Spamming)
                if (hash_table[current_idx].count == limit_per_sec) {
                    write_log_error("[SEC] Rate limit exceeded for IP: %s (Limit: %d req/sec)", 
                                     client_ip, limit_per_sec);
                    hash_table[current_idx].count++; // Naikkan agar log tidak muncul lagi di detik ini
                }
                pthread_mutex_unlock(&rate_limit_mutex);
                return false; // RATE LIMIT EXCEEDED
            }
        }

        i++; // Lanjut cari slot berikutnya kalau tabrakan
    }

    pthread_mutex_unlock(&rate_limit_mutex);
    return true; 
}

void sec_traffic_start_janitor() {
    pthread_t janitor_tid;

    // 1. Bersihkan tabel pertama kali pas server start
    reset_rate_limits();

    // Membuat thread janitor untuk membersihkan rate limit setiap 10 menit
    if (pthread_create(&janitor_tid, NULL, janitor_thread, NULL) == 0) {
        pthread_detach(janitor_tid); // Agar thread berjalan mandiri
        write_log("[SEC] Defense System: Janitor background service activated.");
    }
}

void sec_traffic_anti_slow_loris(int sock_client) {
    // 1. Set Keep-Alive di level TCP (Biar OS yang ngecek kalau client 'ghosting')
    int keepalive = 1;
    setsockopt(sock_client, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    // 2. TCP_NODELAY (Nagle's Algorithm)
    // HANYA pasang ini kalau kamu TIDAK pakai TCP_CORK saat kirim file.
    // Karena kamu pakai TCP_CORK di send_static, NODELAY ini sebaiknya DIMATIKAN 
    // agar CORK bisa bekerja maksimal menggabungkan paket.
    int nodelay = 0; 
    setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    // 3. Pasang LINGER (PENTING buat Reliability 'ab')
    // Ini memastikan saat close(), kernel bakal nunggu sebentar biar data terkirim semua.
    struct linger sl;
    sl.l_onoff = 1;
    sl.l_linger = 2; // Tunggu 2 detik sebelum benar-benar memutus koneksi
    setsockopt(sock_client, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

    // 4. Timeout Recv/Send (Hanya efektif jika socket kembali ke mode Blocking)
    // Tapi tetap bagus buat 'jaring pengaman' terakhir.
    struct timeval tv;
    tv.tv_sec = 5; 
    tv.tv_usec = 0;
    setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// Algoritma DJB2 Hash - Sangat cepat untuk string (IP Address)
unsigned long hash_ip(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash % HASH_TABLE_SIZE;
}

// Fungsi private
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
    // Log Janitor: Penting untuk tahu tabel hash kita tidak penuh (collision)
    if(cleared > 0) {
        write_log("[SEC] Janitor service: Cleared %d inactive IP entries from table.", cleared);
    }
}

void* janitor_thread(void* arg) {
    (void)arg;
    while(1) {
        sleep(600); // Tidur 10 menit
        clean_old_rate_limits();
    }
    return NULL;
}