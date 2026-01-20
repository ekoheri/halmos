#ifndef FASTCGI_H
#define FASTCGI_H

#include <stddef.h>

#include "http1_handler.h"

#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_PARAMS 4
#define FCGI_RESPONDER 1
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_END_REQUEST 3

#define FCGI_KEEP_CONN 1 // Flag untuk pooling

// Struktur header FastCGI
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

// Struktur untuk permintaan Begin Request FastCGI
typedef struct {
    FCGI_Header header;
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    char *header;
    char *body;
} FastCGI_Response;

// Fungsi yang diperbarui
void send_begin_request(int sockfd, int request_id, int keep_conn);

FastCGI_Response cgi_request_stream(
    RequestHeader *req,
    int sock_client,
    const char *target_ip,
    int target_port,
    void *post_data,          
    size_t post_data_len,     
    size_t content_length
);

#endif