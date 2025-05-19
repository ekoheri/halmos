#ifndef KEYGEN_H
#define KEYGEN_H

#define MAX_ROWS 10
#define MAX_COLS 21
#define MAX_WORD_LENGTH 50
#define MAX_INPUT_LENGTH 256
#define HASH_SIZE 1024
#define DEFAULT_KEY "Halmos123"

extern char cipher_sengkalan[MAX_ROWS][MAX_COLS][256];

typedef struct HashNode {
    char word[MAX_WORD_LENGTH];
    int row;
    struct HashNode *next;
} HashNode;

typedef struct HashTable {
    HashNode *table[HASH_SIZE];
} HashTable;

char* generate_otp();
void encrypt_sengkalan();
void sengkalan_array_to_string(
    char cipher_sengkalan[MAX_ROWS][MAX_COLS][256], 
    int rows, 
    int cols[], 
    char *output, 
    size_t output_size);
char *sengkalan_encode(const char *input);
char *sengkalan_decode(const char *input);

#endif // OTP_H