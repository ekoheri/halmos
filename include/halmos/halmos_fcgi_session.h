#ifndef HALMOS_FCGI_SESSION_H
#define HALMOS_FCGI_SESSION_H

#include "halmos_http1_header.h"
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <openssl/ssl.h>

// Definisi state FSM untuk Async FastCGI
typedef enum {
    FCGI_STATE_INIT = 0,
    FCGI_STATE_CONNECTING,
    FCGI_STATE_SENDING_REQ,
    FCGI_STATE_WAITING_RESPONSE,
    FCGI_STATE_READING_STDOUT,
    FCGI_STATE_FINISHED,
    FCGI_STATE_ERROR
} FCGI_AsyncState;

typedef struct {
    int sock_client;            // Socket klien (untuk HTTP/1) atau socket HTTP2Session fd
    int fpm_fd;                 // Socket upstream PHP-FPM
    bool is_tls;                // Apakah koneksi klien menggunakan TLS
    SSL *ssl_conn;              // Konteks SSL klien (jika TLS aktif untuk HTTP/1)
    
    // --- TAMBAHAN DUKUNGAN HTTP/2 ---
    bool is_http2;              // true jika ini berasal dari request HTTP/2, false jika HTTP/1
    uint32_t http2_stream_id;   // ID Stream HTTP/2 yang bersangkutan
    // --------------------------------

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
} HalmosFCGISession;

// Prototip fungsi manajemen sesi
HalmosFCGISession* halmos_fcgi_session_create(int sock_client, bool is_tls, SSL *ssl_conn, RequestHeader *req, int backend_type);
void halmos_fcgi_session_destroy(HalmosFCGISession *session);
void halmos_fcgi_session_set_state(HalmosFCGISession *session, FCGI_AsyncState new_state);

#endif // HALMOS_FCGI_SESSION_H