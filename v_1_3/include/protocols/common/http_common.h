#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include <stddef.h>
#include <stdbool.h>

// Tipe respon (Memory vs File) tetap sama di semua versi HTTP
typedef enum {
    RES_TYPE_MEMORY,
    RES_TYPE_FILE
} ResponseType;

// Struktur data Multipart tetap sama karena format body-nya standar
typedef struct {
    char *name;
    char *filename;
    char *content_type;
    void *data;
    size_t data_len;
} MultipartPart;

// Struktur Respon Akhir yang akan dikirim ke client
typedef struct {
    ResponseType type;
    int status_code;
    const char *status_message;
    const char *mime_type;
    void *content;      // Buffer atau Path File
    size_t length;
    const char *http_version;
} HalmosResponse;

#endif