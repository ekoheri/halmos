#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <ctype.h>
#include <png.h>

#include "../include/steganography.h"

/* Pengolahan gambar PNG */

typedef struct {
    uint8_t r, g, b, alpha;
} Pixel;

typedef struct {
    Pixel *data;
    size_t width, height;
} Image;

// Fungsi untuk membaca file PNG
int ReadPNG(const char *filename, Image *image) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open file");
        return -1;
    }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fclose(fp);
        return -1;
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return -1;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return -1;
    }

    png_init_io(png, fp);
    png_read_info(png, info);

    image->width = png_get_image_width(png, info);
    image->height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    if (bit_depth == 16) png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);

    if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png);

    png_read_update_info(png, info);

    image->data = malloc(image->width * image->height * sizeof(Pixel));
    png_bytep *rows = malloc(image->height * sizeof(png_bytep));
    for (size_t y = 0; y < image->height; y++) {
        rows[y] = (png_bytep)(image->data + y * image->width);
    }

    png_read_image(png, rows);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    free(rows);
    return 0;
}

// Fungsi untuk menyimpan file PNG
int WritePNG(const char *filename, const Image *image) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open file");
        return -1;
    }

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fclose(fp);
        return -1;
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_write_struct(&png, NULL);
        fclose(fp);
        return -1;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        return -1;
    }

    png_init_io(png, fp);
    png_set_IHDR(png, info, image->width, image->height, 8,
                 PNG_COLOR_TYPE_RGB_ALPHA, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    png_bytep *rows = malloc(image->height * sizeof(png_bytep));
    for (size_t y = 0; y < image->height; y++) {
        rows[y] = (png_bytep)(image->data + y * image->width);
    }

    png_write_image(png, rows);
    png_write_end(png, NULL);

    png_destroy_write_struct(&png, &info);
    fclose(fp);
    free(rows);
    return 0;
}

/* Steganografy */
char* DecimalToHexa(int inputNumber, int padLength) {
    // Hitung panjang heksadesimal dari inputNumber
    char* hexRepresentation = (char*)malloc((padLength + 1) * sizeof(char));
    if (!hexRepresentation) {
        return NULL; // Handle jika malloc gagal
    }

    // Konversi ke heksadesimal
    snprintf(hexRepresentation, padLength + 1, "%0*X", padLength, inputNumber);

    return hexRepresentation;
}

int HexaToInteger(const char* hexString) {
    return (int)strtol(hexString, NULL, 16);
}

bool HexaIsvalid(const char* hexaStr, int padLength) {
    // Periksa panjang string
    if (strlen(hexaStr) != padLength) {
        return false;
    }

    // Periksa setiap karakter
    for (int i = 0; i < padLength; i++) {
        if (!isxdigit(hexaStr[i])) {
            return false;
        }
    }

    return true;
}

int Inject(const char *filecover, const char *filestego,const char *message) {
    Image image;

    // Baca file PNG
    if (ReadPNG(filecover, &image) != 0) {
        printf("Failed to read %s\n", filecover);
        return -1;
    }

    size_t msg_len_size = strlen(message);
    char *msg_len_hexa = DecimalToHexa(msg_len_size, 6);

    size_t inject_msg_size = strlen(msg_len_hexa) + strlen(message) + 1;
    char *inject_msg = malloc(inject_msg_size);
    if (!inject_msg) {
        perror("Gagal mengalokasikan memori");
        free(image.data);
        return -1;
        //exit(EXIT_FAILURE);
    }

    strcpy(inject_msg, msg_len_hexa);
    strcat(inject_msg, message);

    for (int i = 0; i < strlen(inject_msg); i++) {
        Pixel *px = &image.data[i];
        char c = inject_msg[i];
        unsigned char asciiCode = (unsigned char)c;
        unsigned char _maskR = (asciiCode & 0x03) >> 0;
        unsigned char _maskG = (asciiCode & 0x0C) >> 2;
        unsigned char _maskB = (asciiCode & 0x30) >> 4;
        unsigned char _maskA = (asciiCode & 0xC0) >> 6;

        px->r = (px->r & 0xFC) | _maskR;
        px->g = (px->g & 0xFC) | _maskG;
        px->b = (px->b & 0xFC) | _maskB;
        px->alpha = (px->alpha & 0xFC) | _maskA;
        //printf("%d\t%d\t%d\t%d\n", px->r, px->g, px->b, px->alpha);
    }

    if (WritePNG(filestego, &image) != 0) {
        printf("Failed to write %s\n", filestego);
        free(image.data);
        return -1;
    }

    free(msg_len_hexa); 
    free(inject_msg);
    free(image.data);

    return 0;
}

char* Extract(const char *filestego) {
    Image image;

    // Baca file PNG
    if (ReadPNG(filestego, &image) != 0) {
        printf("Failed to read %s\n", filestego);
        return NULL;
    }

    size_t index = 0;
    size_t extract_count = 0;
    size_t number_of_msg = 0;
    bool completed = false;

    // Alokasikan memori awal untuk membaca panjang pesan
    char *hidden_msg = malloc(image.width * image.height * 4);
    if (!hidden_msg) return NULL;

    size_t total_pixels = image.width * image.height;

    if (image.data == NULL || total_pixels == 0) {
        free(hidden_msg);
        return NULL;
    }

    while (index < total_pixels && !completed) {
        Pixel *px = &image.data[index];

        // Ekstrak 2-bit dari setiap komponen pixel
        unsigned char _2bitLSB_A = (px->r & 0x03) << 0;
        unsigned char _2bitLSB_B = (px->g & 0x03) << 2;
        unsigned char _2bitLSB_G = (px->b & 0x03) << 4;
        unsigned char _2bitLSB_R = (px->alpha & 0x03) << 6;

        unsigned char asciiCode = _2bitLSB_A | _2bitLSB_B | _2bitLSB_G | _2bitLSB_R;

        if (number_of_msg == 0) {
            // Masukkan karakter ke buffer untuk membaca panjang pesan
            hidden_msg[extract_count] = (char)asciiCode;
            //hidden_msg[extract_count + 1] = '\0'; // Null-terminate sementara untuk debugging
            //printf("Extracting length: %s\n", hidden_msg);

            if (extract_count == 5) { // Panjang pesan selesai dibaca
                //printf("Hexa : %s\n", hidden_msg);
                if (HexaIsvalid(hidden_msg, 6)) {
                    number_of_msg = HexaToInteger(hidden_msg);
                    //printf("Total pesan : %zu\n", number_of_msg);

                    // Alokasikan ulang memori untuk pesan asli
                    free(hidden_msg);
                    hidden_msg = malloc(number_of_msg + 1); // Tambahkan null-terminator
                    if (!hidden_msg) return NULL;

                    memset(hidden_msg, 0, number_of_msg + 1);
                    extract_count = 0; // Reset untuk membaca pesan
                } else {
                    free(image.data);
                    free(hidden_msg);
                    return NULL;
                }
            } else {
                extract_count++;
            }
        } else {
            // Mulai membaca pesan sebenarnya
            hidden_msg[extract_count] = (char)asciiCode;
            // Null-terminate sementara untuk debugging
            //hidden_msg[extract_count + 1] = '\0'; 
            //printf("Extracting message: %s\n", hidden_msg);

            extract_count++;
            if (extract_count == number_of_msg) {
                completed = true;
            }
        }

        index++;
    }

    if (!completed) {
        free(image.data);
        free(hidden_msg);
        return NULL;
    }

    free(image.data);
    return hidden_msg;
}
