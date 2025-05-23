#ifndef HTTP_H
#define HTTP_H

typedef struct {
    char method[16];
    char *directory;
    char *uri;
    char http_version[16];
    char *query_string;
    char *path_info;
    char *body_data;
    char *request_time;
    char *encrypted;
    char *content_type;
    int content_length;
} RequestHeader;

typedef struct {
    const char *http_version;
    int status_code;
    const char *status_message;
    const char *mime_type;
    unsigned long content_length;
    const char *response_time;
    const char *encrypted;
} ResponseHeader;

RequestHeader parse_request_line(char *request);

char *handle_method(int *response_size, RequestHeader req_header);
#endif