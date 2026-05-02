#ifndef HALMOS_HTTP2_RESPONSE_H
#define HALMOS_HTTP2_RESPONSE_H

#include "halmos_http2_core.h"

/**
 * Mengirim 200 OK atau status lainnya via H2
 * Header harus dikompres dulu pakai HPACK sebelum dikirim
 */
void http2_response_send_header(HTTP2Session *session, HTTP2Stream *stream, int status_code);

/**
 * Mengirim Body/File via H2 DATA Frame
 * Di sini kita harus membagi file besar menjadi potongan-potongan frame (misal per 16KB)
 */
void http2_response_send_data(HTTP2Session *session, HTTP2Stream *stream, const void *data, size_t len, bool is_end);

/**
 * Jembatan antara routing umum Halmos ke pengiriman H2
 */
void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream);

#endif