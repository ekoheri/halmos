#ifndef HALMOS_FCGI_PROTO_H
#define HALMOS_FCGI_PROTO_H

#include "halmos_http1_header.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Definisi Struktur Header FastCGI (8 Byte)
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} __attribute__((packed)) FCGI_Header;

// Konstanta Tipe Record FastCGI
#define FCGI_VERSION_1           1
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11

// Konstanta Role & Flag FastCGI (Pastikan baris ini ada!)
#define FCGI_RESPONDER           1
#define FCGI_KEEP_CONN           1

// Konstanta Role & Flag FastCGI (Pastikan baris ini ada!)
#define FCGI_RESPONDER           1
#define FCGI_KEEP_CONN           1

void fcgi_proto_begin_request(unsigned char *gather_buf, int *g_ptr, int request_id);
void fcgi_proto_build_params(RequestHeader *req, int sock_client, size_t content_length, unsigned char *gather_buf, int *g_ptr, int request_id);
size_t fcgi_proto_build_stdin_record(int request_id, const void *data, size_t data_len, unsigned char *out_buf, size_t max_out_len);
size_t fcgi_proto_build_empty_stdin_record(int request_id, unsigned char *out_buf, size_t max_out_len);

#endif // HALMOS_FCGI_PROTO_H