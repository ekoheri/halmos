#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "halmos_fcgi.h"
#include "halmos_log.h"

/**
 * fcgi_api_request_stream
 * Fungsi fasad utama yang mengatur koordinasi antar modul FCGI.
 */

int fcgi_api_request_stream(RequestHeader *req, int sock_client, const char *target, int port, void *post_data, size_t content_length) {
    int request_id = 1;
    unsigned char gather_buf[16384];
    int g_ptr = 0;

    // 1. BEGIN REQUEST
    int fpm_sock = fcgi_proto_begin_request(target, port, gather_buf, &g_ptr, request_id);
    if (fpm_sock == -1) return -1;

    // 2. BUILD PARAMS
    fcgi_proto_build_params(req, sock_client, content_length, gather_buf, &g_ptr, request_id);

    // 3. SEND & RECEIVE
    return fcgi_proto_send_and_receive(fpm_sock, sock_client, req, request_id, gather_buf, g_ptr, post_data, content_length);
}