#ifndef HALMOS_FCGI_SESSION_H
#define HALMOS_FCGI_SESSION_H

#include "halmos_http1_header.h"
#include "halmos_http2_core.h"

#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <openssl/ssl.h>
#include <stdatomic.h>

// Ukuran Ring Buffer statis per sesi (menggantikan malloc dinamis yang boros RAM)
#define FCGI_RING_BUFFER_SIZE 4096  // 8192 //16384  // 16KB per buffer (cukup untuk chunking / streaming)
#define MAX_FCGI_SESSIONS     128   //256  //1024   // Kapasitas maksimum global pool sesi konkuren

// Definisi state FSM untuk Async FastCGI
typedef enum {
    FCGI_SESSION_FREE = 0,      // Slot kosong di dalam global pool
    FCGI_STATE_INIT,
    FCGI_STATE_CONNECTING,
    FCGI_STATE_SENDING_REQ,
    FCGI_STATE_WAITING_RESPONSE,
    FCGI_STATE_READING_STDOUT,
    FCGI_STATE_FINISHED,
    FCGI_STATE_ERROR
} FCGI_AsyncState;

// Struktur Ring Buffer Statis
typedef struct {
    char data[FCGI_RING_BUFFER_SIZE];
    size_t head;
    size_t tail;
    size_t size;
} FCGIRingBuffer;

// Struct Sesi FastCGI yang sepenuhnya statis (Pre-allocated di Global Pool)
typedef struct FCGI_Session {
    int session_id;             // Indeks unik sesi di dalam Global Pool (0 hingga MAX_FCGI_SESSIONS - 1)
    int sock_client;            // Socket klien (untuk HTTP/1) atau socket HTTP2Session fd
    int fpm_fd;                 // Socket upstream PHP-FPM
    bool is_tls;                // Apakah koneksi klien menggunakan TLS
    SSL *ssl_conn;              // Konteks SSL klien (jika TLS aktif untuk HTTP/1)

    // --- ATOMIC REFERENCE COUNTING ---
    atomic_int ref_count;
    
    // --- DUKUNGAN HTTP/2 ---
    bool is_http2;              // true jika ini berasal dari request HTTP/2, false jika HTTP/1
    uint32_t http2_stream_id;   // ID Stream HTTP/2 yang bersangkutan

    // Field Buffer & State FSM untuk HTTP/1
    bool is_fcgi_active;
    bool fcgi_header_parsed;
    unsigned char fcgi_header_buf[512]; // Dibatasi ukuran fix yang aman untuk header fastcgi
    size_t fcgi_h_ptr;

    // --- PENGGANTI MALLOC DINAMIS (RING BUFFER STATIS) ---
    FCGIRingBuffer rx_buffer;   // Buffer terima data dari PHP-FPM (menggantikan malloc gather_buf)
    FCGIRingBuffer tx_buffer;   // Buffer kirim data ke klien
    // ---------------------------------------------------------

    void *h2_session; // Menyimpan pointer HTTP2Session
    void *h2_stream;

    FCGI_AsyncState state;      // Status FSM saat ini

    // Properti pelacakan buffer & record FastCGI
    int header_pos;
    bool header_sent;
    bool is_redirect;
    
    size_t current_content_len;
    size_t current_padding_len;
    size_t bytes_processed_in_record;
    time_t last_activity;

    pthread_mutex_t lock;       // Mutex pengaman thread-safe lokal sesi
} FCGI_Session;

// Prototip fungsi manajemen Global Session Pool
bool fcgi_global_pool_init(int max_sessions);
void fcgi_global_pool_destroy(void);

FCGI_Session* fcgi_session_slot_get(int session_id);

// Fungsi Manajemen Sesi berbasis Pool (Tanpa malloc/free di tengah jalan)
FCGI_Session* fcgi_session_create(int sock_client, bool is_tls, SSL *ssl_conn, RequestHeader *req, int backend_type);
void fcgi_session_set_state(FCGI_Session *session, FCGI_AsyncState new_state);
FCGI_Session* fcgi_session_acquire(FCGI_Session *session);
void fcgi_session_release(FCGI_Session *session);

// Operasi Ring Buffer Statis
size_t fcgi_ring_write(FCGIRingBuffer *rb, const char *src, size_t len);
size_t fcgi_ring_read(FCGIRingBuffer *rb, char *dest, size_t max_len);
void fcgi_ring_clear(FCGIRingBuffer *rb);

#endif // HALMOS_FCGI_SESSION_H