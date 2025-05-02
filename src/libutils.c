#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/libutils.h"

void bytes_to_hex(const uint8_t* bytes, char* hex, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[bytes_len * 2] = '\0';
}

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Base64 encode table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 encode
char *base64_encode(const unsigned char *input, size_t len) {
    size_t output_len = 4 * ((len + 2) / 3);
    char *output = malloc(output_len + 1);
    if (!output) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? input[i++] : 0;
        uint32_t octet_b = i < len ? input[i++] : 0;
        uint32_t octet_c = i < len ? input[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = (i > len + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        output[j++] = (i > len) ? '=' : base64_table[triple & 0x3F];
    }

    output[j] = '\0';
    return output;
}

// Base64 decode
unsigned char *base64_decode(const char *input, size_t *out_len) {
    size_t len = strlen(input);
    if (len % 4 != 0) return NULL;

    size_t output_len = len / 4 * 3;
    if (input[len - 1] == '=') output_len--;
    if (input[len - 2] == '=') output_len--;

    unsigned char *output = malloc(output_len + 1);
    if (!output) return NULL;

    uint32_t buffer = 0;
    size_t i, j, k = 0;
    for (i = 0; i < len;) {
        for (j = 0; j < 4; j++) {
            buffer <<= 6;
            char c = input[i++];
            if (c >= 'A' && c <= 'Z') buffer |= c - 'A';
            else if (c >= 'a' && c <= 'z') buffer |= c - 'a' + 26;
            else if (c >= '0' && c <= '9') buffer |= c - '0' + 52;
            else if (c == '+') buffer |= 62;
            else if (c == '/') buffer |= 63;
            else if (c == '=') buffer |= 0;
        }

        if (k < output_len) output[k++] = (buffer >> 16) & 0xFF;
        if (k < output_len) output[k++] = (buffer >> 8) & 0xFF;
        if (k < output_len) output[k++] = buffer & 0xFF;
    }

    output[output_len] = '\0';
    *out_len = output_len;
    return output;
}