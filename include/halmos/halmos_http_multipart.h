#ifndef HALMOS_HTTP_MULTIPART_H
#define HALMOS_HTTP_MULTIPART_H

#include "halmos_http1_header.h"

/**
 * Memproses body request dan memecahnya menjadi bagian-bagian (parts).
 * Mengisi array parts di dalam struct RequestHeader.
 */
void http_multipart_parse_body(RequestHeader *req);

/**
 * Membebaskan memori yang dialokasikan untuk setiap part multipart.
 */
void http_multipart_free_parts(MultipartPart *parts, int count);

#endif