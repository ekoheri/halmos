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
    HalmosFCGI_Conn *connections;
    int pool_size;
    
    /* --- Jatah Adaptive --- */
    int php_quota;
    int rust_quota;
    int python_quota;
    
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

/* --- GLOBAL EXTERN --- */
extern HalmosFCGI_Pool fcgi_pool;

/* * ==========================================
 * 1. POOL MANAGEMENT (halmos_fcgi_pool.c)
 * ==========================================
 */
void halmos_fcgi_pool_init(void);
void halmos_fcgi_pool_destroy(void);
int  halmos_fcgi_conn_acquire(const char *target, int port);
void halmos_fcgi_conn_release(int sockfd);

/* * ==========================================
 * 2. PROTOCOL & MARSHALLING (halmos_fcgi_proto.c)
 * ==========================================
 */
// Merakit semua Params menjadi satu buffer besar
int halmos_fcgi_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id);

void halmos_fcgi_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id);

int halmos_fcgi_send_and_receive(int fpm_sock, int sock_client, RequestHeader *req, int request_id, unsigned char *gather_buf, int g_ptr, void *post_data, size_t content_length);

// Mengirim data STDIN (Body POST)
void halmos_fcgi_send_stdin(int sockfd, int request_id, const void *data, int data_len);

// Helper internal untuk pasangan key-value
int  add_fcgi_pair(unsigned char* dest, const char *name, const char *value, int offset, int max_len);

/* * ==========================================
 * 3. I/O & STREAMING (halmos_fcgi_io.c)
 * ==========================================
 */
// Fungsi berat yang melakukan Zero-Copy Splice
int  halmos_fcgi_splice_response(int fpm_fd, int sock_client, RequestHeader *req);

/* * ==========================================
 * 4. PUBLIC API (halmos_fcgi.c)
 * ==========================================
 */
// Fungsi fasad yang dipanggil oleh manager http
int halmos_fcgi_request_stream(RequestHeader *req, int sock_client, const char *target, int port, void *post_data, size_t content_length);

#endif