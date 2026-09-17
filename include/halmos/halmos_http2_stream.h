#ifndef HALMOS_HTTP2_STREAM_H
#define HALMOS_HTTP2_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include "halmos_http2_core.h"

HTTP2Stream* http2_stream_find_unlocked(HTTP2Session *session, uint32_t id);
HTTP2Stream* http2_stream_find(HTTP2Session *session, uint32_t id);
uint32_t http2_stream_get_bucket_fibonacci(uint32_t stream_id);

#endif // HALMOS_HTTP2_STREAM_H