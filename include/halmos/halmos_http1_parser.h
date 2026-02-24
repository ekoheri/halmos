#ifndef HALMOS_HTTP1_PARSER_H
#define HALMOS_HTTP1_PARSER_H

#include "halmos_http1_header.h"

// Prototipe Fungsi khusus HTTP/1
// Ini di implementasikan di http1_parser.c
bool http1_parser_parse_header(char *raw_data, size_t total_received, RequestHeader *req);
void http1_parser_free_memory(RequestHeader *req);

//pindah ke manager
//void handle_method(int sock_client, RequestHeader req_header);

#endif
