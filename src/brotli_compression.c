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
    size_t compressed_size;
    unsigned char *compressed = base64_decode(input_base64, &compressed_size);
    if (!compressed) return NULL;

    size_t output_buf_size = compressed_size * 6;
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
        free(output);
        return NULL;
    }

    char *output_str = malloc(output_buf_size + 1);
    if (!output_str) {
        free(output);
        return NULL;
    }

    memcpy(output_str, output, output_buf_size);
    output_str[output_buf_size] = '\0';
    *output_size = output_buf_size;
    free(output);
    return output_str;
}

/*int main() {
    const char *original = "Ini adalah data yang akan dikompresi menggunakan Brotli.";
    size_t original_size = strlen(original);

    uint8_t *compressed = malloc(BUFFER_SIZE);
    uint8_t *decompressed = malloc(BUFFER_SIZE);

    // Kompresi
    size_t compressed_size = compress_brotli((const uint8_t*)original, original_size, compressed, BUFFER_SIZE);
    if (compressed_size == 0) {
        printf("Kompresi gagal.\n");
        return 1;
    }

    // Tampilkan hasil kompresi dalam hex
    printf("Data terkompresi (%zu byte):\n", compressed_size);
    for (size_t i = 0; i < compressed_size; i++) {
        printf("%02X ", compressed[i]);
    }
    printf("\n");

    // Dekompresi
    size_t decompressed_size = decompress_brotli(compressed, compressed_size, decompressed, BUFFER_SIZE);
    if (decompressed_size == 0) {
        printf("Dekompresi gagal.\n");
        return 1;
    }

    // Tambahkan null-terminator
    decompressed[decompressed_size] = '\0';
    printf("Hasil dekompresi: %s\n", decompressed);

    free(compressed);
    free(decompressed);
    return 0;
}*/
