#ifndef MULTIPART_H
#define MULTIPART_H

#include "../protocols/common/http_common.h"
#include "../protocols/http1/http1_parser.h"
#include "../core/fs_handler.h"

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