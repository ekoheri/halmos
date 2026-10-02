#ifndef HALMOS_FCGI_POOL_H
#define HALMOS_FCGI_POOL_H

#include <stdatomic.h> // untuk operasi lock-free atomic_int
#include <stdbool.h>
#include <pthread.h>

/* Individual connection status */
typedef struct {
    int sockfd;
    int target_port;      // Untuk TCP
    char target_path[108]; // Untuk AF_UNIX (max path length sun_path)
    bool is_unix;          // Flag pembeda
    bool in_use;
} FCGI_Conn;

typedef struct {
    int node_count;               // Jumlah node yang terdeteksi dari config
    atomic_int next_idx;     // Penunjuk untuk Round Robin
} UpstreamGroup;

/* Global Pool Manager */
typedef struct {
    FCGI_Conn *connections;
    int pool_size;
    
    /* --- Jatah Adaptive (Atomic per Backend) --- */
    // Index 0: PHP, 1: Rust, 2: Python
    atomic_int active_counts[3]; 

    // Grouping
    UpstreamGroup php_group;
    UpstreamGroup rust_group;
    UpstreamGroup python_group;

    /* Quota per backend (diambil dari config saat init) */
    int php_quota;
    int rust_quota;
    int python_quota;
    
    /* Statistik (Opsional, untuk monitoring) */
    int current_idle_count; 

    pthread_mutex_t lock;
} FCGI_Pool;

/* --- GLOBAL EXTERN --- */
extern FCGI_Pool fcgi_pool;

/* * ==========================================
 * 1. POOL MANAGEMENT (halmos_fcgi_pool.c)
 * ==========================================
 */
void fcgi_pool_init(void);

void fcgi_pool_destroy(void);

int  fcgi_pool_conn_acquire(const char *target, int port);

void fcgi_pool_conn_release(int sockfd);

unsigned int hash_ip(const char *ip);

#endif