#ifndef HTTP1_HANDLER_H
#define HTTP1_HANDLER_H

#include "http1_parser.h"

// Entry point utama yang dipanggil dari http1_parser.c
void handle_method(int sock_client, RequestHeader req_header);

// Spesialis Statis (GET file .html, .css, .jpg dll)
void handle_static_request(int sock_client, RequestHeader *req);

// Spesialis Dinamis (GET/POST untuk .php, .rs, .py dll)
void handle_dynamic_request(int sock_client, RequestHeader *req);

#endif