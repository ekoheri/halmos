#ifndef HALMOS_HTTP2_FILE_H
#define HALMOS_HTTP2_FILE_H

#include <stdbool.h>
#include "halmos_http2_core.h"

//http2_flush_active_streams_file
void http2_file_flush_active_streams(HTTP2Session *session);

//http2_has_active_file_streams
bool http2_file_has_active_streams(HTTP2Session *session);

#endif // HALMOS_HTTP2_FILE_H