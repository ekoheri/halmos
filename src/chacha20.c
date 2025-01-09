#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "../include/chacha20.h"
#include "../include/libutils.h"

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

char* encrypt(
    const char *plaintext, 
    const char *key, long length) {

    uint8_t *ciphertext_bytes = malloc(length);
    if (!ciphertext_bytes) {
        return NULL;
    }

    uint32_t block[16] = {0};

    // Memisahkan `key` dan `nonce` dari parameter `key`
    memcpy(block, key, 32);      // 32 byte pertama sebagai kunci
    memcpy(block + 8, key + 32, 8);  // 8 byte terakhir sebagai nonce
    block[12] = counter;

    uint32_t output_block[16];
    
    for (uint32_t i = 0; i < length; i++) {
        if (i % CHACHA20_BLOCK_SIZE == 0) {
            chacha20_block(output_block, block);  // Membuat blok enkripsi baru
            block[12]++;                          // Meningkatkan counter setiap blok
        }
        ciphertext_bytes[i] = plaintext[i] ^ ((uint8_t*)output_block)[i % CHACHA20_BLOCK_SIZE];
    }

    char *ciphertext_hex = malloc(length * 2 + 1);
    if (!ciphertext_hex) {
        free(ciphertext_bytes);
        return NULL;
    }
    bytes_to_hex(ciphertext_bytes, ciphertext_hex, length);

    free(ciphertext_bytes);
    return ciphertext_hex;
}

char* decrypt(const char *ciphertext, const char *key, long length) {
    uint8_t *ciphertext_bytes = malloc(length);
    if (!ciphertext_bytes) {
        return NULL;
    }

    // Mengonversi ciphertext dari hex ke bytes
    hex_to_bytes(ciphertext, ciphertext_bytes, length);

    uint8_t *plaintext_bytes = malloc(length);
    if (!plaintext_bytes) {
        free(ciphertext_bytes);
        return NULL;
    }

    uint32_t block[16] = {0};
    
    // Mengambil kunci (32 byte pertama dari key) dan nonce (8 byte terakhir dari key)
    memcpy(block, key, 32);          // 32 byte pertama sebagai kunci
    memcpy(block + 8, key + 32, 8);  // 8 byte terakhir sebagai nonce
    block[12] = counter;             // Menggunakan counter yang diberikan

    uint32_t output_block[16];
    
    // Proses dekripsi dengan XOR
    for (uint32_t i = 0; i < length; i++) {
        if (i % CHACHA20_BLOCK_SIZE == 0) {
            chacha20_block(output_block, block);  // Membuat blok baru dari chacha20
            block[12]++;                          // Meningkatkan counter setiap blok
        }
        plaintext_bytes[i] = ciphertext_bytes[i] ^ ((uint8_t*)output_block)[i % CHACHA20_BLOCK_SIZE];
    }

    char *plaintext = malloc(length + 1);  // Mengalokasikan memori untuk hasil dekripsi
    if (!plaintext) {
        free(ciphertext_bytes);
        free(plaintext_bytes);
        return NULL;
    }

    memcpy(plaintext, plaintext_bytes, length);  // Menyalin hasil dekripsi ke dalam plaintext
    plaintext[length] = '\0';  // Menambahkan null terminator

    free(ciphertext_bytes);
    free(plaintext_bytes);
    return plaintext;
}

// compile : gcc -shared -o chacha20 -fPIC enkripsi/chacha20.c
