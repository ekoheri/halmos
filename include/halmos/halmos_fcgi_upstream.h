#ifndef HALMOS_FCGI_UPSTREAM_H
#define HALMOS_FCGI_UPSTREAM_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http1_header.h"

#include <netinet/in.h>
#include <sys/un.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

/* Individual connection slot status */
typedef struct {
    int sockfd;
    int target_port;         // Untuk TCP
    char target_path[108];   // Untuk AF_UNIX (max path length sun_path)
    bool is_unix;            // Flag pembeda jenis socket
    bool in_use;
} HalmosFCGI_Conn;

/* Grouping untuk Load Balancing Round-Robin */
typedef struct {
    int node_count;          // Jumlah node yang terdeteksi dari config
    atomic_int next_idx;     // Penunjuk atomic untuk Round Robin
} UpstreamGroup;

/* Global Upstream Manager (Bersih dari istilah pool) */
typedef struct {
    HalmosFCGI_Conn *connections;
    int slots;
    
    /* --- Jatah Adaptive (Atomic per Backend) --- */
    // Index 0: PHP, 1: Rust, 2: Python
    atomic_int active_counts[3];

    /* Grouping per Bahasa */
    UpstreamGroup php_group;
    UpstreamGroup rust_group;
    UpstreamGroup python_group;

    /* Quota per backend (diambil dari config saat init) */
    int php_quota;
    int rust_quota;
    int python_quota;
    
    /* Statistik & Monitoring */
    int current_idle_count;

    pthread_mutex_t lock;
} HalmosFCGI_Upstream;

/* Instance global upstream manager */
extern HalmosFCGI_Upstream fcgi_upstream;

/* Fungsi-fungsi manajemen upstream */
void halmos_fcgi_upstream_init(void);
void halmos_fcgi_upstream_destroy(void);
int halmos_fcgi_upstream_acquire(const char *target, int port);
void halmos_fcgi_upstream_release(int sockfd);
int halmos_fcgi_upstream_select_node(RequestHeader *req, int backend_type, const char **out_ip, int *out_port, bool *out_is_unix);

#endif // HALMOS_FCGI_UPSTREAM_H