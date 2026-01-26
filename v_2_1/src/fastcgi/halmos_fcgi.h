#ifndef HALMOS_FCGI_H
#define HALMOS_FCGI_H

#include "halmos_http1_header.h"

#include <stddef.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/un.h> // Include untuk AF_UNIX


/* FastCGI Protocol Definitions */
#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_END_REQUEST 3
#define FCGI_RESPONDER 1
#define FCGI_KEEP_CONN 1

/* Pool Configuration */
#define MAX_HALMOS_FCGI_POOL 64 

/* --- Data Structures --- */

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} HalmosFCGI_Header;

/* Individual connection status */
typedef struct {
    int sockfd;
    int target_port;      // Untuk TCP
    char target_path[108]; // Untuk AF_UNIX (max path length sun_path)
    bool is_unix;          // Flag pembeda
    bool in_use;
} HalmosFCGI_Conn;

/* Global Pool Manager */
typedef struct {
    HalmosFCGI_Conn connections[MAX_HALMOS_FCGI_POOL];
    int current_idle_count;
    pthread_mutex_t lock;
    char target_ip[16];
    int target_port;
} HalmosFCGI_Pool;

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

typedef struct {
    char *header;
    char *body;
    size_t body_len; /* Mendukung data biner dari Rust/PHP */
} HalmosFCGI_Response;

extern HalmosFCGI_Pool fcgi_pool;

/* --- Core Lifecycle Functions --- */

/**
 * Inisialisasi pool koneksi FastCGI.
 * Dipanggil sekali saat startup server.
 */
void halmos_fcgi_pool_init(void);

/**
 * Mengambil koneksi aktif dari pool (Thread-Safe).
 * Jika pool kosong, fungsi ini akan membuka socket baru ke backend.
 */
int halmos_fcgi_conn_acquire(const char *target, int port);

/**
 * Mengembalikan koneksi ke pool agar bisa digunakan kembali.
 * Jika pool sudah penuh (MAX_HALMOS_FCGI_POOL), socket akan ditutup.
 */
void halmos_fcgi_conn_release(int sockfd);

/**
 * Membersihkan seluruh pool saat shutdown.
 */
void halmos_fcgi_pool_destroy(void);

/* --- Request Handling --- */

/**
 * Eksekusi request ke FastCGI backend (Rust, PHP, dll).
 * Menggunakan internal buffering untuk efisiensi system call.
 */
int halmos_fcgi_request_stream(
    RequestHeader *req,
    int sock_client,
    const char *target,
    int port,
    void *post_data,          
    size_t post_data_len,      
    size_t content_length
);

/**
 * Dealokasi memori response.
 */
void halmos_fcgi_pool_init(void);

int halmos_fcgi_request_stream(
    RequestHeader *req,
    int sock_client,
    const char *target,  // Tambahkan ini (bisa IP "127.0.0.1" atau path "/tmp/php.sock")
    int port,            // Tambahkan ini (9000 untuk TCP, atau 0 untuk Unix Socket)
    void *post_data,
    size_t post_data_len,
    size_t content_length
);

void halmos_fcgi_pool_destroy(void);
#endif