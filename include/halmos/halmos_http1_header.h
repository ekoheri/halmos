#ifndef HALMOS_HTTP1_HEADER_H
#define HALMOS_HTTP1_HEADER_H

#include <stddef.h>
#include <stdbool.h>

#include "halmos_http_route.h"

/* --- KONSTANTA UKURAN BUFFER STATIS --- */
#define HTTP2_URI_MAX            1024
#define HTTP2_HOST_MAX            256
#define HTTP2_COOKIE_MAX         1024
#define HTTP2_CONTENT_TYPE_MAX    128
#define HTTP2_QUERY_BUF_MAX       512

// Tipe respon (Memory vs File) tetap sama di semua versi HTTP
typedef enum {
    RES_TYPE_MEMORY,
    RES_TYPE_FILE
} ResponseType;

// Struktur data Multipart tetap sama karena format body-nya standar
typedef struct {
    char *name;
    char *filename;
    char *content_type;
    void *data;
    size_t data_len;
} MultipartPart;

// Info WebSocket biasanya melalui proses 'Upgrade' di HTTP/1.1
typedef struct {
    char *key;
    char *protocol;
    bool is_valid;
} WebSocketInfo;

// Struktur RequestHeader ini sangat spesifik HTTP/1 (berbasis teks/string)
typedef struct {
    char client_ip[45];
    char method[16];        // Statis, aman
    char http_version[16];   // Statis, aman
    
    // POINTER ZERO-COPY (Hanya menunjuk ke buffer di manager)
    char *uri;
    char *host;
    char *directory;
    char *query_string;
    char query_string_buffer[512];
    char *path_info;
    char *content_type;
    char *cookie_data;
    void *vhost_context;
    FcgiBackend backend_type;

    // BUFFER FISIK (Landing Strip)
    // Tempat penyimpanan hasil transformasi agar pointer di atas tetap valid
    char route_result[512];

    // INLINE LANDING STRIP BUFFER (Khusus HTTP/2 Dekode HPACK agar Zero-Allocation)
    char h2_uri_buf[HTTP2_URI_MAX];
    char h2_host_buf[HTTP2_HOST_MAX];
    char h2_content_type_buf[HTTP2_CONTENT_TYPE_MAX];
    char h2_cookie_buf[HTTP2_COOKIE_MAX];

    // Status Error (0 = Normal, 414 = URI Too Long, 431 = Header Too Large)
    int error_code;
    
    //STATUS TLS/BUKAN
    bool is_tls;

    // BODY ZERO-COPY
    void *body_data;        // Menunjuk langsung ke offset di buffer manager
    size_t body_length;
    int content_length;
    
    bool is_keep_alive; 
    bool is_upgrade;
    bool is_valid;      
    
    WebSocketInfo ws;
    MultipartPart *parts;   // Array-nya tetap malloc, tapi isinya zero-copy
    int parts_count;
} RequestHeader;

// Struktur Respon Akhir yang akan dikirim ke client
typedef struct {
    ResponseType type;
    int status_code;
    const char *status_message;
    const char *mime_type;
    void *content;      // Buffer atau Path File
    size_t length;
    const char *http_version;
} HalmosResponse;

#endif