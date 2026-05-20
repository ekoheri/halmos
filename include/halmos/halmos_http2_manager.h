#ifndef HALMOS_HTTP2_MANAGER_H
#define HALMOS_HTTP2_MANAGER_H

#include "halmos_http2_core.h"

/**
 * Handler untuk tipe frame yang masuk
 */
void http2_send_frame(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len);

void http2_handle_headers_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);

void http2_handle_data_frame(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);

/**
 * Main Loop untuk HTTP/2
 * Menggantikan http1_manager_session
 */
int http2_manager_session(int sock_client, bool is_tls);

uint32_t get_bucket_fibonacci(uint32_t stream_id);
#endif