#ifndef HTTP1_PARSER_H
#define HTTP1_PARSER_H

#include "../common/http_common.h" // Butuh MultipartPart & HalmosResponse

// Info WebSocket biasanya melalui proses 'Upgrade' di HTTP/1.1
typedef struct {
    char *key;
    char *protocol;
    bool is_valid;
} WebSocketInfo;

// Struktur RequestHeader ini sangat spesifik HTTP/1 (berbasis teks/string)
typedef struct {
    char method[16];
    char *directory;
    char *uri;
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
} RequestHeader;

// Prototipe Fungsi khusus HTTP/1
// Ini di implementasikan di http1_parser.c
bool parse_http_request(const char *buffer, size_t size, RequestHeader *req);
void free_request_header(RequestHeader *req);
void handle_method(int sock_client, RequestHeader req_header);

// Ini di implementasikan di http1_manager.c
int handle_http1_session(int sock_client);
#endif