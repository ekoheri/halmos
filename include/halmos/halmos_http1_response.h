#ifndef HTTP1_HALMOS_RESPONSE_H
#define HTTP1_HALMOS_RESPONSE_H

#include <stddef.h>
#include <stdbool.h>
#include "halmos_http1_header.h"

// Nama fungsi harus persis dengan yang ada di response.c ente
void send_mem_response_plain(int client_fd, int status_code, const char *status_text, const char *content, bool keep_alive);

void process_request_routing(int sock_client, RequestHeader *req);

void static_response_zerocopy(int sock_client, RequestHeader *req);

#endif