#ifndef HALMOS_H2_HUFFMAN_H
#define HALMOS_H2_HUFFMAN_H

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

//char* http2_huffman_decode(const unsigned char *src, size_t len);
bool http2_huffman_decode(const unsigned char *src, size_t len, char *dest, size_t dest_size);

#endif