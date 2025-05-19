#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

//char *encrypt(const char *plaintext, const char *key, long length);
//char *decrypt(const char *ciphertext, const char *key, long length);

uint8_t* chacha20_crypt(const uint8_t *input, size_t len, const uint8_t key[32], const uint8_t nonce[12]);

#endif