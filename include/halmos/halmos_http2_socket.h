#ifndef HALMOS_HTTP2_SOCKET_H
#define HALMOS_HTTP2_SOCKET_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "halmos_http2_core.h"

ssize_t http2_socket_write(int fd, bool is_tls, const void *buf, size_t len);

ssize_t http2_socket_read(int fd, bool is_tls, void *buf, size_t len);

void http2_socket_write_or_buffer(HTTP2Session *session, int fd, bool is_tls, const unsigned char *data, size_t len);

int http2_socket_flush_pending_write(HTTP2Session *session);

#endif // HALMOS_HTTP2_SOCKET_H