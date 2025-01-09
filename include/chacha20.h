#ifndef CHACHA20_H
#define CHACHA20_H

char *encrypt(const char *plaintext, const char *key, long length);
char *decrypt(const char *ciphertext, const char *key, long length);

#endif