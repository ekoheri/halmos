#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char *key;
    char *protocol;
    bool is_valid;
} WebSocketInfo;

typedef struct {
    char *name;
    char *filename;
    char *content_type;
    void *data;
    size_t data_len;
} MultipartPart;

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
    bool is_upgrade;
    bool is_valid;      // <--- Pastikan baris ini ada
    WebSocketInfo ws; // Modularitas terkumpul di sini
    MultipartPart *parts;
    int parts_count;
} RequestHeader;

typedef enum {
    RES_TYPE_MEMORY,
    RES_TYPE_FILE
} ResponseType;

typedef struct {
    ResponseType type;
    int status_code;
    const char *status_message;
    const char *mime_type;
    void *content;      // Buffer atau Path File
    size_t length;
    const char *http_version;
} HalmosResponse;

// Prototipe Fungsi
RequestHeader parse_request_line(char *request, size_t total_received);
void handle_method(int sock_client, RequestHeader req_header);
void send_mem_response(int sock, int code, const char *msg, const char *body);
void parse_multipart_body(RequestHeader *req);
void free_request_header(RequestHeader *req);

#endif