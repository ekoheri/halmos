#ifndef HALMOS_HTTP2_PARSER_H
#define HALMOS_HTTP2_PARSER_H

#include "halmos_http2_core.h"

// Membaca 9 byte pertama dari socket
bool http2_parse_frame_header(const unsigned char *buf, HTTP2FrameHeader *out);

// HPACK: Mendekompres binary header menjadi string yang dimengerti RequestHeader
bool http2_hpack_decode(HTTP2Session *session, HTTP2Stream *stream, const unsigned char *payload, size_t len);

void http2_parser_free_memory(HTTP2Stream *stream);
#endif