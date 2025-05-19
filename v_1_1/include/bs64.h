#ifndef BS64_H
#define BS64_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

char *base64_encode(const unsigned char *input, size_t len);
uint8_t *base64_decode(const char *input, size_t *out_len);
#endif
