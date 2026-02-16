#ifndef HALMOS_SECURITY_H
#define HALMOS_SECURITY_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>

// Tentukan ukuran table (Gunakan angka prima agar distribusi hash bagus)
#define HASH_TABLE_SIZE 10007

// Struktur data utama
typedef struct {
    char ip[46];            // Support IPv6 (max 45 chars)
    int count;              // Jumlah request
    time_t window_start;    // Detik saat ini
} RateEntry;

/**
 * Pengecekan apakah request diperbolehkan.
 * Meskipun kamu bilang cuma clean_old yang dipanggil, fungsi ini 
 * biasanya wajib ada di header supaya bisa dipakai di event loop/worker.
 */
bool is_request_allowed(const char *client_ip, int limit_per_sec);


/*
 * Firewall anti slow solaris. Yaitu koneksi yang bertengger
 * disitu, tetapi tidak ngapa-ngapain. Hanya menghabiskan tempat saja 
*/
void anti_slow_loris(int sock_client);

/**
 * Membersihkan data IP yang sudah tidak aktif lebih dari 10 detik.
 * Fungsi ini yang kamu jadikan 'Janitor' di background thread.
 */
// void clean_old_rate_limits();

/**
 * Reset total semua data rate limit.
 */
void reset_rate_limits();

/*
* FUngsi untuk membersihkan IP user yang nyangkut di RAM 
*/
void start_janitor();

#endif
