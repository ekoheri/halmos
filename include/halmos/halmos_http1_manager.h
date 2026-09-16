#ifndef HALMOS_HTTP1_MANAGER_H
#define HALMOS_HTTP1_MANAGER_H

#include <stdbool.h>
#include <sys/types.h>
#include "halmos_core_conn_table.h"
#include "halmos_http1_header.h"

// Enumerasi state sesi HTTP/1 untuk mendukung arsitektur non-blocking / event-driven
typedef enum {
    STATE_READ_HEADERS = 0,
    STATE_READ_BODY,
    STATE_HANDLE_REQUEST,
    STATE_SEND_STATIC_FILE,
    STATE_HANDLE_FASTCGI,
    STATE_DONE
} HTTP1State;

typedef struct {
    char *buffer;
    size_t buf_len;
    size_t buf_capacity;
    RequestHeader req;

    // Status / State Sesi Saat Ini
    HTTP1State state;

    // --- TAMBAHAN: STATE PENGIRIMAN FILE / RESPONS (RESUMABLE) ---
    int file_fd;                // File descriptor file statis (-1 jika tidak aktif)
    off_t file_offset;          // Posisi byte file terakhir yang sukses dikirim
    size_t file_remaining;      // Total ukuran file / sisa byte
    
    // --- TAMBAHAN: STATE PENGIRIMAN HEADER ---
    char header_buf[1024];      // Buffer untuk header respons
    size_t header_len;          // Panjang total header
    size_t header_sent_offset;  // Byte header yang sudah terkirim
    bool is_header_sent;        // Flag apakah header sudah 100% terkirim

    int fcgi_sock;
} HTTP1Session;

void http1_session_destroy(void *session);

int http1_manager_session(halmos_conn_t *conn);

// Fungsi penanganan respons SSL / File Statis terintegrasi
int http1_manager_ssl_response(halmos_conn_t *conn, HTTP1Session *session);

int http1_manager_plain_response(int sock_client, HTTP1Session *session);

#endif