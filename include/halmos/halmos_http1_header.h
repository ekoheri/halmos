#ifndef HALMOS_HTTP1_HEADER_H
#define HALMOS_HTTP1_HEADER_H

#include <stddef.h>
#include <stdbool.h>

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
    char *query_string;
    char *content_type;
    char *cookie_data;
    
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