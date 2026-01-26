#ifndef HTTP1_HALMOS_RESPONSE_H
#define HTTP1_HALMOS_RESPONSE_H

#include <stddef.h>
#include <stdbool.h>
#include "halmos_http1_header.h"            // Butuh HalmosResponse

/**
 * Mengirimkan respon HTTP/1.1 lengkap ke client.
 * Fungsi ini akan merangkai status line, headers, dan body.
 */
void send_halmos_response(int sock_client, HalmosResponse res, bool keep_alive);

/**
 * Fungsi shortcut untuk mengirim respon cepat dari memori (seperti 404 atau 400).
 */
void send_mem_response(int sock_client, int status, const char *msg, const char *content, bool keep_alive);

/**
 * Fungsi khusus untuk melayani permintaan file statis dari disk.
 */
void process_request_routing(int sock_client, RequestHeader *req);

void static_response(int sock_client, RequestHeader *req);

void dynamic_response(int sock_client, RequestHeader req_header);

#endif
