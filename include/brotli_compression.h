#ifndef BROTLI_COMPRESSION_H
#define BROTLI_COMPRESSION_H

char *compress_brotli(const char *input, size_t input_size);
char *decompress_brotli(const char *input_base64, size_t *output_size);

#endif