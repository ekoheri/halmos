#ifndef LIBUTILS_H
#define LIBUTILS_H

void bytes_to_hex(const uint8_t* bytes, char* hex, size_t bytes_len);
void hex_to_bytes(const char* hex, uint8_t* bytes, size_t bytes_len);
void base64_encode(const unsigned char *input, int len, char *output);
int base64_decode(const char *input, unsigned char *output);
#endif
