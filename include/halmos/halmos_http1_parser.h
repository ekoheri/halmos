#ifndef HALMOS_HTTP1_PARSER_H
#define HALMOS_HTTP1_PARSER_H

#include "halmos_http1_header.h"

// Prototipe Fungsi khusus HTTP/1
// Ini di implementasikan di http1_parser.c
bool parse_http_request(char *raw_data, size_t total_received, RequestHeader *req);
void free_request_header(RequestHeader *req);

//pindah ke manager
//void handle_method(int sock_client, RequestHeader req_header);

#endif
