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

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *input, int len, char *output) {
    int i, j;
    for (i = 0, j = 0; i < len;) {
        unsigned int octet_a = i < len ? input[i++] : 0;
        unsigned int octet_b = i < len ? input[i++] : 0;
        unsigned int octet_c = i < len ? input[i++] : 0;

        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = (i > len + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        output[j++] = (i > len) ? '=' : base64_table[triple & 0x3F];
    }
    output[j] = '\0';
}

int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; // invalid character
}

int base64_decode(const char *input, unsigned char *output) {
    int len = strlen(input);
    int i = 0, j = 0;
    uint32_t buffer = 0;
    int bits_collected = 0;

    while (i < len) {
        int val = base64_char_value(input[i]);
        if (val >= 0) {
            buffer = (buffer << 6) | val;
            bits_collected += 6;

            if (bits_collected >= 8) {
                bits_collected -= 8;
                output[j++] = (buffer >> bits_collected) & 0xFF;
            }
        } else if (input[i] != '=' && input[i] != '\n' && input[i] != '\r') {
            // skip invalid characters or line breaks
            return -1; // error
        }
        i++;
    }

    return j; // jumlah byte hasil decode
}
