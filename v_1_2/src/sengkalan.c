#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "../include/sengkalan.h"
#include "../include/config.h"
#include "../include/sha256.h"
#include "../include/chacha20.h"
#include "../include/bs64.h"
#include "../include/libutils.h"

extern Config config;

char cipher_sengkalan[MAX_ROWS][MAX_COLS][256] = {0};

char List_Sengkalan[MAX_ROWS][MAX_COLS][100] = {
    {"akasa", "awang-awang", "barakan", "brastha", "byoma", "doh", "gegana", "ilang", "kombul", "kos", "langit", "luhur", "mesat", "mletik", "muksa", "muluk", "musna", "nenga", "ngles", "nir", "nis"},
    {"badan", "budha", "budi", "buweng", "candra", "dara", "dhara", "eka", "gusti", "hyang", "iku", "jagat", "kartika", "kenya", "lek", "luwih", "maha", "nabi", "nata", "nekung", "niyata"},
    {"apasang", "asta", "athi-athi", "buja", "bujana", "dresthi", "dwi", "gandheng", "kalih", "kanthi", "kembar", "lar", "mandeng", "myat", "nayana", "nembeh", "netra", "ngabekti", "paksa", "sikara", "sungu"},
    {"agni", "api", "apyu", "bahni", "benter", "brama", "dahana", "guna", "jatha", "kaeksi", "katingalan", "katon", "kawruh", "kaya", "kobar", "kukus", "lir", "murub", "nala", "naut", "nauti"},
    {"bun", "catur", "dadya", "gawe", "her", "jaladri", "jalanidhi", "karta", "karti", "karya", "keblat", "marna", "marta", "masuh", "nadi", "papat", "pat", "samodra", "sagara", "sindu", "suci"},
    {"angin", "astra", "bajra", "bana", "bayu", "buta", "cakra", "diyu", "galak", "gati", "guling", "hru", "indri", "indriya", "jemparing", "lima", "lungid", "marga", "margana", "maruta", "nata"},
    {"amla", "anggana", "anggang-anggang", "amnggas", "artati", "carem", "glinggang", "hoyag", "ilat", "karaseng", "karengya", "kayasa", "kayu", "kilatan", "lidhah", "lindhu", "lona", "manis", "naya", "nem", "nenem"},
    {"acala", "ajar", "angsa", "ardi", "arga", "aswa", "biksu", "biksuka", "dwija", "giri", "gora", "himawan", "kaswareng", "kuda", "muni", "nabda", "pandhita", "pitu", "prabata", "resi", "sabda"},
    {"anggusti", "astha", "bajul", "basu", "basuki", "baya", "bebaya", "brahma", "brahmana", "bujangga", "dirada", "dwipa", "dwipangga", "dwirada", "estha", "esthi", "gajah", "kunjara", "madya", "liman", "madya"},
    {"ambuka", "anggangsir", "angleng", "angrong", "arum", "babahan", "bedah", "bolong", "butul", "dewa", "dwara", "ganda", "gapura", "gatra", "guwa", "jawata", "kori", "kusuma", "lawang", "manjing", "masuk"}
};

void encrypt_sengkalan() {
    const char *hash_key = sha256_hash(config.default_key_sengkalan);

    uint8_t buffer_key[44];
    hex_to_bytes(hash_key, buffer_key, 32);
    uint8_t key[32];
    uint8_t nonce[12];
    memcpy(key, buffer_key, 32);
    memcpy(nonce, buffer_key + 20, 12);

    for (int i = 0; i < MAX_ROWS; i++) {
        for (int j = 0; j < MAX_COLS; j++) {
            size_t temp_cipher_size = strlen(List_Sengkalan[i][j]);
            uint8_t *temp_cipher = chacha20_crypt((uint8_t *)List_Sengkalan[i][j], temp_cipher_size, key, nonce);
            char *temp_cipher_b64 = base64_encode(temp_cipher, temp_cipher_size);
            strncpy(
                cipher_sengkalan[i][j], 
                temp_cipher_b64, 
                strlen(temp_cipher_b64)
            );
            cipher_sengkalan[i][j][sizeof(cipher_sengkalan[i][j]) - 1] = '\0'; // Pastikan null-terminated
        }
    }
}

void sengkalan_array_to_string(char cipher_sengkalan[MAX_ROWS][MAX_COLS][256], int rows, int cols[], char *output, size_t output_size) {
    char buffer[1024]; // Buffer sementara untuk tiap baris
    size_t current_length = 0;

    // Inisialisasi string output
    output[0] = '\0';

    // Looping setiap baris
    for (int i = 0; i < rows; i++) {
        // Tambahkan pembuka kurung kurawal
        strcat(output, "{");
        current_length += 1;

        // Looping setiap kolom di baris i
        for (int j = 0; j < cols[i]; j++) {
            // Tambahkan elemen ke buffer sementara
            snprintf(buffer, sizeof(buffer), "%s%s", j > 0 ? "," : "", cipher_sengkalan[i][j]);

            // Pastikan panjang total tidak melebihi batas
            if (current_length + strlen(buffer) >= output_size - 1) {
                fprintf(stderr, "Output buffer terlalu kecil.\n");
                return;
            }

            // Gabungkan buffer sementara ke output
            strcat(output, buffer);
            current_length += strlen(buffer);
        }

        // Tambahkan penutup kurung kurawal
        strcat(output, "}");
        current_length += 1;

        // Tambahkan koma dan newline jika bukan baris terakhir
        if (i < rows - 1) {
            strcat(output, ",\n");
            current_length += 2;
        }
    }
}

char* generate_otp() {
    // Seed untuk generator angka acak
    srand((unsigned int)time(NULL));
    
    // Alokasi memori untuk string OTP (4 digit + null terminator)
    char *otp = malloc(5);
    if (otp == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Menghasilkan 4 digit acak
    for (int i = 0; i < 4; i++) {
        otp[i] = '0' + (rand() % 10); // Menghasilkan angka dari 0 hingga 9
    }
    otp[4] = '\0'; // Menambahkan null terminator di akhir string

    return otp;
}

// Fungsi hash untuk mengonversi string menjadi indeks
unsigned int hash(const char *word) {
    unsigned int hash = 5381;
    int c;
    while ((c = *word++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % HASH_SIZE;
}

// Fungsi untuk menambahkan kata ke hash table
void insert(HashTable *ht, const char *word, int row) {
    unsigned int index = hash(word);
    HashNode *newNode = malloc(sizeof(HashNode));
    if (newNode == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    strcpy(newNode->word, word);
    newNode->row = row;
    newNode->next = ht->table[index];
    ht->table[index] = newNode;
}

// Fungsi untuk mencari kata di hash table
int search(HashTable *ht, const char *word) {
    unsigned int index = hash(word);
    HashNode *node = ht->table[index];
    while (node != NULL) {
        if (strcmp(node->word, word) == 0) {
            return node->row; // Mengembalikan baris yang ditemukan
        }
        node = node->next;
    }
    return -1; // Tidak ditemukan
}

char *sengkalan_encode(const char *input) {
    srand(time(NULL)); // Inisialisasi seed untuk fungsi rand()
    char *sentence = malloc(MAX_INPUT_LENGTH);
    if (sentence == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    sentence[0] = '\0'; // Inisialisasi string kosong

    for (int i = strlen(input) - 1; i >= 0; i--) {
        int index = input[i] - '0'; // Konversi karakter ke digit
        if (index >= 0 && index < MAX_ROWS) {
            int random_index = rand() % MAX_COLS; // Pilih indeks acak 0-21
            if (strlen(sentence) > 0) {
                strcat(sentence, "|"); // Tambahkan | sebagai pemisah
            }
            strcat(sentence, cipher_sengkalan[index][random_index]);
        }
    }
    return sentence;
}

char *sengkalan_decode(const char *input) {
    static char number[MAX_INPUT_LENGTH] = "";
    number[0] = '\0'; // Inisialisasi string kosong

    char *koreksi = (char *)malloc(strlen(input) + 1);
    if (koreksi == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Salin input ke buffer koreksi tanpa perubahan karena pemisah adalah spasi
    strcpy(koreksi, input);

    // Inisialisasi hash table
    HashTable ht = {0};

    // Tambahkan kata ke hash table
    for (int rows = 0; rows < MAX_ROWS; rows++) {
        for (int cols = 0; cols < MAX_COLS; cols++) {
            if (cipher_sengkalan[rows][cols][0] != '\0') {
                insert(&ht, cipher_sengkalan[rows][cols], rows);
            }
        }
    }

    // Proses input menggunakan spasi sebagai pemisah
    char *segment = strtok(koreksi, " ");
    while (segment != NULL) {
        int row = search(&ht, segment);
        if (row != -1) {
            sprintf(number + strlen(number), "%d", row); // Tambahkan angka hasil
        }
        segment = strtok(NULL, " "); // Lanjutkan ke segmen berikutnya
    }

    free(koreksi); // Bebaskan memori

    // Balikkan string hasil
    int len = strlen(number);
    for (int i = 0; i < len / 2; i++) {
        char temp = number[i];
        number[i] = number[len - i - 1];
        number[len - i - 1] = temp;
    }

    return number;
}