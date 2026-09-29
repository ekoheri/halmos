#ifndef HALMOS_H2_HPACK_H
#define HALMOS_H2_HPACK_H

#include "halmos_http1_header.h"
#include "halmos_http2_core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

// HARUS PERSIS SEPERTI INI:
#define NGHTTP2_HUFF_ACCEPTED 1          // 0x01
#define NGHTTP2_HUFF_SYM      (1 << 1)   // 0x02
//#define NGHTTP2_HUFF_FAIL     (1 << 2) // 0x04 -> Tambahkan ini!

typedef struct {
    uint16_t fstate;
    uint8_t flags;
    uint8_t sym;
} nghttp2_huff_decode; // Namanya samakan saja biar tidak bingung

extern const nghttp2_huff_decode huff_decode_table[][16];

uint32_t http2_hpack_decode_int(const unsigned char **pos, const unsigned char *end, uint8_t prefix_mask);

bool http2_hpack_get_header(HTTP2Session *session, uint32_t index, const char **name, const char **value);

void http2_hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value);

bool http2_hpack_decode_string_buf(const unsigned char **pos, const unsigned char *end, char *out_buf, size_t out_max);

int http2_hpack_literal_header_with_name(const char *name, const char *value, RequestHeader *req);

int http2_hpack_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req) ;
#endif