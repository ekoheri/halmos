#ifndef HALMOS_HTTP2_PARSER_H
#define HALMOS_HTTP2_PARSER_H

#include "halmos_http2_core.h"

void http2_parser_handle_headers(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);

// Membaca 9 byte pertama dari socket
void http2_parser_handle_data(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);

bool http2_parser_frame_header(const unsigned char *buf, HTTP2FrameHeader *out);

void http2_parser_free_memory(HTTP2Stream *stream);
#endif