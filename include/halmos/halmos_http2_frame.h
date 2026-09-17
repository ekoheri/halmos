#ifndef HALMOS_HTTP2_FRAME_H
#define HALMOS_HTTP2_FRAME_H

#include <stdint.h>
#include <stdbool.h>
#include "halmos_http2_core.h"

void http2_frame_send(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len);
void http2_frame_send_settings(int fd, bool is_tls);
void http2_frame_send_settings_ack(int fd, bool is_tls);
void http2_frame_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment);
void http2_frame_handle_window_update(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);
/**
 * Handler untuk tipe frame yang masuk
 */

#endif // HALMOS_HTTP2_FRAME_H