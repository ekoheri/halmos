#ifndef BROTLI_COMP_H
#define BROTLI_COMP_H

uint8_t *compress_brotli(const char *input, size_t input_size, size_t *compressed_size);
char *decompress_brotli(const uint8_t *compressed, size_t compressed_size, size_t *output_size);

#endif