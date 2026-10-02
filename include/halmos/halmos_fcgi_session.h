#ifndef HALMOS_FCGI_SESSION_H
#define HALMOS_FCGI_SESSION_H

#include "halmos_http1_header.h"
#include "halmos_http2_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* --- ENUMERASI STATE FSM SESI FASTCGI --- */
typedef enum {
    FCGI_SES_STATE_INIT = 0,
    FCGI_SES_STATE_SENDING_PARAMS,
    FCGI_SES_STATE_SENDING_STDIN,
    FCGI_SES_STATE_RECEIVING,
    FCGI_SES_STATE_FINISHED,
    FCGI_SES_STATE_ERROR
} FCGISessionState;

/* --- ENUMERASI KODE STATUS RETURN STEP --- */
typedef enum {
    FCGI_SES_STATUS_CONTINUE = 0,  // Sesi masih berjalan, butuh event I/O berikutnya
    FCGI_SES_STATUS_COMPLETED = 1, // Sesi request selesai dengan sukses
    FCGI_SES_STATUS_ERROR = -1     // Terjadi error/kegagalan pada sesi
} FCGISessionStatus;

//#ifndef GATHER_BUF_SIZE
//#define GATHER_BUF_SIZE 65536
//#endif

/* --- STRUKTUR UTAMA SESI FASTCGI --- */
typedef struct {
    int client_sock;                 // File descriptor soket klien
    int fpm_sock;                    // File descriptor soket backend PHP-FPM (dari pool)
    int request_id;                  // ID request FastCGI
    FCGISessionState state;          // State machine saat ini

    // Buffer dan penjejak pengiriman Header/Params
    unsigned char gather_buf[GATHER_BUF_SIZE];
    int g_ptr;                       // Total panjang byte di dalam gather_buf
    int g_sent;                      // Jumlah byte gather_buf yang sudah sukses terkirim

    // Data Body / STDIN (POST, PUT, dll)
    const void *post_data;
    size_t content_length;
    size_t stdin_sent;               // Penjejak byte POST data yang sudah dikirim ke FPM

    // Referensi Header HTTP Klien
    RequestHeader *req;
} FCGISession;

/* --- DEKLARASI FUNGSI PUBLIK MODUL SESSION --- */

/**
 * Membuat dan menginisialisasi sesi baru.
 * Di dalamnya otomatis mengambil koneksi FPM dari pool (Opsi 1) dan meracik parameter awal.
 */
FCGISession *fcgi_session_http1_create(int client_sock, int backend_type, RequestHeader *req, void *post_data, size_t content_length, int request_id);

int fcgi_session_http2_create(RequestHeader *req, int backend_type);
/**
 * Menghancurkan objek sesi dan mengembalikan koneksi FPM ke pool (atau menutupnya jika error/poisoned).
 */
void fcgi_session_destroy(FCGISession *session);

/**
 * Menjalankan satu langkah State Machine (FSM Step) berdasarkan event I/O (epoll/poll).
 * Mengembalikan FCGISessionStatus (CONTINUE, COMPLETED, atau ERROR).
 */
int fcgi_session_http1_step(FCGISession *session, uint32_t revents);

int fcgi_session_http2_step(HTTP2Session *session, HTTP2Stream *stream, uint32_t revents);
#endif /* HALMOS_FCGI_SESSION_H */