#ifndef HALMOS_MULTIPART_H
#define HALMOS_MULTIPART_H

#include "halmos_http1_header.h"

/**
 * Memproses body request dan memecahnya menjadi bagian-bagian (parts).
 * Mengisi array parts di dalam struct RequestHeader.
 */
void parse_multipart_body(RequestHeader *req);

/**
 * Membebaskan memori yang dialokasikan untuk setiap part multipart.
 */
void free_multipart_parts(MultipartPart *parts, int count);

#endif