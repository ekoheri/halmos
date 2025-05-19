#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "../include/bs64.h"

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

static const uint8_t base64_reverse_table[256] = {
    [0 ... 255] = 0x80, // default invalid
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,
    ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
    ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
    ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
    ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
    ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
    ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
    ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
    ['='] = 0,
};

uint8_t *base64_decode(const char *input, size_t *out_len) {
    size_t len = strlen(input);
    if (len % 4 != 0) return NULL;

    size_t padding = 0;
    if (len >= 2 && input[len - 1] == '=') padding++;
    if (len >= 2 && input[len - 2] == '=') padding++;

    *out_len = (len / 4) * 3 - padding;
    uint8_t *output = malloc(*out_len);
    if (!output) return NULL;

    size_t i, j;
    uint32_t sextet_a, sextet_b, sextet_c, sextet_d;
    for (i = 0, j = 0; i < len;) {
        sextet_a = base64_reverse_table[(unsigned char)input[i++]];
        sextet_b = base64_reverse_table[(unsigned char)input[i++]];
        sextet_c = base64_reverse_table[(unsigned char)input[i++]];
        sextet_d = base64_reverse_table[(unsigned char)input[i++]];

        if ((sextet_a | sextet_b | sextet_c | sextet_d) & 0x80) {
            free(output);
            return NULL; // karakter tidak valid
        }

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < *out_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < *out_len) output[j++] = triple & 0xFF;
    }

    return output;
}
