#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

#include "../include/libutils.h"
#include "../include/brotli_compression.h"

#define BUFFER_SIZE 1024 * 1024

// Fungsi kompresi Brotli
char *compress_brotli(const char *input, size_t input_size) {
    size_t max_output_size = BrotliEncoderMaxCompressedSize(input_size);
    uint8_t *compressed = malloc(max_output_size);
    if (!compressed) return NULL;

    if (!BrotliEncoderCompress(
            BROTLI_DEFAULT_QUALITY,
            BROTLI_DEFAULT_WINDOW,
            BROTLI_MODE_TEXT,
            input_size,
            (const uint8_t *)input,
            &max_output_size,
            compressed)) {
        free(compressed);
        return NULL;
    }

    char *b64 = base64_encode(compressed, max_output_size);
    free(compressed);
    return b64;
}

// Fungsi dekompresi Brotli
char *decompress_brotli(const char *input_base64, size_t *output_size) {
    // Langkah 1: Decode base64 → hasil: string hex
    char *hexstr = base64_decode(input_base64);  // hasil: "ABCDEF..."
    if (!hexstr) return NULL;

    size_t hex_len = strlen(hexstr);
    if (hex_len % 2 != 0) {
        free(hexstr);
        return NULL;  // panjang hex harus genap
    }

    // Langkah 2: Convert hex string → binary
    size_t compressed_size = hex_len / 2;
    uint8_t *compressed = malloc(compressed_size);
    if (!compressed) {
        free(hexstr);
        return NULL;
    }
    hex_to_bytes(hexstr, compressed, compressed_size);
    free(hexstr);  // tidak dibutuhkan lagi

    // Langkah 3: Brotli decompress
    size_t output_buf_size = compressed_size * 2;  // Estimasi yang lebih aman
    uint8_t *output = malloc(output_buf_size);
    if (!output) {
        free(compressed);
        return NULL;
    }

    BrotliDecoderResult result = BrotliDecoderDecompress(
        compressed_size,
        compressed,
        &output_buf_size,
        output
    );
    free(compressed);

    if (result != BROTLI_DECODER_RESULT_SUCCESS) {
        fprintf(stderr, "Brotli decompression failed: %d\n", result);
        free(output);
        return NULL;
    }

    // Langkah 4: Ubah ke string biasa
    char *output_str = malloc(output_buf_size + 1);
    if (!output_str) {
        free(output);
        return NULL;
    }

    // Hanya menyalin ukuran yang benar sesuai dengan hasil dekompresi
    memcpy(output_str, output, output_buf_size);
    output_str[output_buf_size] = '\0';  // null-terminate

    free(output);

    // Menyimpan ukuran output, jika diminta
    if (output_size) {
        *output_size = output_buf_size;
    }

    return output_str;
}
