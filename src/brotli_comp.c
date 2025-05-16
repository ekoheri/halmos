#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

#include "../include/brotli_comp.h"

#define BUFFER_SIZE 4096

uint8_t *compress_brotli(const char *input, size_t input_size, size_t *compressed_size) {
    size_t max_output_size = BrotliEncoderMaxCompressedSize(input_size);
    uint8_t *compressed = malloc(max_output_size);
    if (!compressed) return NULL;

    // Variable untuk menyimpan ukuran aktual hasil kompresi
    size_t actual_output_size = max_output_size;

    BROTLI_BOOL result = BrotliEncoderCompress(
        BROTLI_DEFAULT_QUALITY,
        BROTLI_DEFAULT_WINDOW,
        BROTLI_MODE_TEXT,
        input_size,
        (const uint8_t *)input,
        &actual_output_size,
        compressed
    );

    if (!result) {
        free(compressed);
        return NULL;
    }

    // Kembalikan ukuran hasil kompresi via parameter pointer
    if (compressed_size) {
        *compressed_size = actual_output_size;
    }

    return compressed;
}

// Fungsi untuk dekompresi menggunakan Brotli
char *decompress_brotli(const uint8_t *compressed, size_t compressed_size, size_t *output_size) {
    size_t output_buf_size = compressed_size * 4; // Estimasi awal
    uint8_t *output = malloc(output_buf_size);
    if (!output) return NULL;

    BrotliDecoderResult result = BrotliDecoderDecompress(
        compressed_size,
        compressed,
        &output_buf_size,
        output
    );

    if (result != BROTLI_DECODER_RESULT_SUCCESS) {
        fprintf(stderr, "Brotli decompression failed: %d\n", result);
        free(output);
        return NULL;
    }

    char *output_str = malloc(output_buf_size + 1);
    if (!output_str) {
        free(output);
        return NULL;
    }

    memcpy(output_str, output, output_buf_size);
    output_str[output_buf_size] = '\0';  // Null-terminate

    free(output);

    if (output_size) {
        *output_size = output_buf_size;
    }

    return output_str;
}