#ifndef HALMOS_FCGI_PROTO_H
#define HALMOS_FCGI_PROTO_H

#include "halmos_http1_header.h"

#include <stddef.h>
#include <sys/un.h> // Include untuk AF_UNIX
#include <sys/types.h>  // Wajib untuk ssize_t
#include <stddef.h>     // Untuk size_t


/* FastCGI Protocol Definitions */
#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_END_REQUEST 3
#define FCGI_RESPONDER 1
#define FCGI_KEEP_CONN 1

/* --- Data Structures --- */

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} HalmosFCGI_Header;

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

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

typedef struct {
    char *header;
    char *body;
    size_t body_len; /* Mendukung data biner dari Rust/PHP */
} HalmosFCGI_Response;

/* * ==========================================
 * 2. PROTOCOL & MARSHALLING (halmos_fcgi_proto.c)
 * ==========================================
 */
// Merakit semua Params menjadi satu buffer besar

int fcgi_proto_begin_request(const char *target, int port, unsigned char *gather_buf, int *g_ptr, int request_id);

void fcgi_proto_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id);

// Mengirim data STDIN (Body POST)
void fcgi_proto_send_stdin(int sockfd, int request_id, const void *data, int data_len);


int fcgi_io_splice_response(int fpm_fd, int sock_client, RequestHeader *req);

#endif