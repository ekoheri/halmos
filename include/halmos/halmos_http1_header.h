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
    char method[16];
    char *directory;
    char *uri;
    char *host;
    char http_version[16];
    char *query_string;
    char *path_info;
    void *body_data;
    size_t body_length;
    char *content_type;
    int content_length;
    bool is_keep_alive; 
    bool is_upgrade;
    bool is_valid;      
    WebSocketInfo ws; // Modularitas terkumpul di sini
    MultipartPart *parts;
    int parts_count;
    char *cookie_data;
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