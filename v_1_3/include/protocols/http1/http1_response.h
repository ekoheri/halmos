#ifndef HTTP1_RESPONSE_H
#define HTTP1_RESPONSE_H

#include <stddef.h>
#include <stdbool.h>
#include "http_common.h" // Butuh HalmosResponse
#include "http1_parser.h"          // Butuh RequestHeader

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
void send_file_response(int client_fd, const char *file_path, const char *mime_type, bool keep_alive);

#endif