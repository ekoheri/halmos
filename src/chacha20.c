#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/chacha20.h"

#define CHACHA20_BLOCK_SIZE 64
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

uint32_t counter = 1; 

void chacha20_block(uint32_t output[16], const uint32_t input[16]) {
    uint32_t state[16];
    memcpy(state, input, 16 * sizeof(uint32_t));

    for (int i = 0; i < 20; i += 2) {
        state[0] += state[4]; state[12] = ROTATE_LEFT(state[12] ^ state[0], 16);
        state[8] += state[12]; state[4] = ROTATE_LEFT(state[4] ^ state[8], 12);
        state[0] += state[4]; state[12] = ROTATE_LEFT(state[12] ^ state[0], 8);
        state[8] += state[12]; state[4] = ROTATE_LEFT(state[4] ^ state[8], 7);

        state[1] += state[5]; state[13] = ROTATE_LEFT(state[13] ^ state[1], 16);
        state[9] += state[13]; state[5] = ROTATE_LEFT(state[5] ^ state[9], 12);
        state[1] += state[5]; state[13] = ROTATE_LEFT(state[13] ^ state[1], 8);
        state[9] += state[13]; state[5] = ROTATE_LEFT(state[5] ^ state[9], 7);

        state[2] += state[6]; state[14] = ROTATE_LEFT(state[14] ^ state[2], 16);
        state[10] += state[14]; state[6] = ROTATE_LEFT(state[6] ^ state[10], 12);
        state[2] += state[6]; state[14] = ROTATE_LEFT(state[14] ^ state[2], 8);
        state[10] += state[14]; state[6] = ROTATE_LEFT(state[6] ^ state[10], 7);

        state[3] += state[7]; state[15] = ROTATE_LEFT(state[15] ^ state[3], 16);
        state[11] += state[15]; state[7] = ROTATE_LEFT(state[7] ^ state[11], 12);
        state[3] += state[7]; state[15] = ROTATE_LEFT(state[15] ^ state[3], 8);
        state[11] += state[15]; state[7] = ROTATE_LEFT(state[7] ^ state[11], 7);

        state[0] += state[5]; state[15] = ROTATE_LEFT(state[15] ^ state[0], 16);
        state[10] += state[15]; state[5] = ROTATE_LEFT(state[5] ^ state[10], 12);
        state[0] += state[5]; state[15] = ROTATE_LEFT(state[15] ^ state[0], 8);
        state[10] += state[15]; state[5] = ROTATE_LEFT(state[5] ^ state[10], 7);

        state[1] += state[6]; state[12] = ROTATE_LEFT(state[12] ^ state[1], 16);
        state[11] += state[12]; state[6] = ROTATE_LEFT(state[6] ^ state[11], 12);
        state[1] += state[6]; state[12] = ROTATE_LEFT(state[12] ^ state[1], 8);
        state[11] += state[12]; state[6] = ROTATE_LEFT(state[6] ^ state[11], 7);

        state[2] += state[7]; state[13] = ROTATE_LEFT(state[13] ^ state[2], 16);
        state[8] += state[13]; state[7] = ROTATE_LEFT(state[7] ^ state[8], 12);
        state[2] += state[7]; state[13] = ROTATE_LEFT(state[13] ^ state[2], 8);
        state[8] += state[13]; state[7] = ROTATE_LEFT(state[7] ^ state[8], 7);

        state[3] += state[4]; state[14] = ROTATE_LEFT(state[14] ^ state[3], 16);
        state[9] += state[14]; state[4] = ROTATE_LEFT(state[4] ^ state[9], 12);
        state[3] += state[4]; state[14] = ROTATE_LEFT(state[14] ^ state[3], 8);
        state[9] += state[14]; state[4] = ROTATE_LEFT(state[4] ^ state[9], 7);
    }

    for (int i = 0; i < 16; i++) {
        output[i] = state[i] + input[i];
    }
}

void prepare_input(uint32_t input[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    // Constants "expand 32-byte k" dalam 4 x uint32_t (little endian)
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;

    // Key (256-bit) 8 kata
    for (int i = 0; i < 8; i++) {
        input[4 + i] = ((uint32_t)key[i * 4]) |
                       ((uint32_t)key[i * 4 + 1] << 8) |
                       ((uint32_t)key[i * 4 + 2] << 16) |
                       ((uint32_t)key[i * 4 + 3] << 24);
    }

    // Counter
    input[12] = counter;

    // Nonce (96 bit) 3 kata
    for (int i = 0; i < 3; i++) {
        input[13 + i] = ((uint32_t)nonce[i * 4]) |
                        ((uint32_t)nonce[i * 4 + 1] << 8) |
                        ((uint32_t)nonce[i * 4 + 2] << 16) |
                        ((uint32_t)nonce[i * 4 + 3] << 24);
    }
}

uint8_t* chacha20_crypt(const uint8_t *input, size_t len, const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t *output = malloc(len);
    if (!output) return NULL;

    uint32_t block[16];
    uint32_t keystream[16];
    size_t i;

    uint32_t counter = 0;

    for (i = 0; i < len; i++) {
        // Set ulang block setiap 64 byte
        if (i % CHACHA20_BLOCK_SIZE == 0) {
            prepare_input(block, key, nonce, counter++);
            chacha20_block(keystream, block);
        }
        output[i] = input[i] ^ ((uint8_t*)keystream)[i % CHACHA20_BLOCK_SIZE];
    }

    return output;
}

