#ifndef MULTIPART_H
#define MULTIPART_H

#include "http_common.h"
#include "http1_parser.h"
#include "fs_handler.h"

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