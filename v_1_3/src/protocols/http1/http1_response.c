#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

/* Gunakan header wrapper yang sudah mencakup common dan http1 */
#include "../include/protocols/common/http_common.h"
#include "../include/protocols/http1/http1_response.h"
#include "../include/core/log.h"

/**
 * Fungsi Internal: Mengirimkan raw teks header HTTP/1.1
 * Ini adalah evolusi dari send_http_headers lama Anda.
 */
static void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive) {
    char header[512];
    const char *conn_status = keep_alive ? "keep-alive" : "close";

    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Server: Halmos-Engine/1.0\r\n"
        "\r\n", 
        res->status_code, res->status_message, 
        res->mime_type, res->length, conn_status);
    
    send(client_fd, header, len, 0);
}

/**
 * Fungsi Utama: Mengirim respon lengkap berdasarkan objek HalmosResponse
 */
void send_halmos_response(int sock_client, HalmosResponse res, bool keep_alive) {
    // 1. Kirim Header
    send_http1_headers(sock_client, &res, keep_alive);

    // 2. Kirim Body jika data ada di memori
    if (res.type == RES_TYPE_MEMORY && res.content != NULL && res.length > 0) {
        send(sock_client, res.content, res.length, 0);
    }
}

/**
 * Shortcut untuk mengirim pesan teks/error cepat
 */
void send_mem_response(int client_fd, int status_code, const char *status_text, 
                       const char *content, bool keep_alive) {
    HalmosResponse res = {
        .type = RES_TYPE_MEMORY,
        .status_code = status_code,
        .status_message = status_text,
        .mime_type = "text/html",
        .content = (void*)content,
        .length = content ? strlen(content) : 0
    };
    
    send_halmos_response(client_fd, res, keep_alive);
}

/**
 * Melayani pengiriman file statis
 */
void send_file_response(int client_fd, const char *file_path, const char *mime_type, bool keep_alive) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        write_log("ERROR", "File not found: %s", file_path);
        send_mem_response(client_fd, 404, "Not Found", "<h1>404 File Not Found</h1>", false);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Siapkan objek respon untuk file
    HalmosResponse res = {
        .type = RES_TYPE_FILE,
        .status_code = 200,
        .status_message = "OK",
        .mime_type = mime_type,
        .length = file_size
    };

    // Kirim Header dulu
    send_http1_headers(client_fd, &res, keep_alive);

    // Kirim isi file per bongkahan (chunk)
    char buffer[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        send(client_fd, buffer, bytes_read, 0);
    }

    fclose(file);
}