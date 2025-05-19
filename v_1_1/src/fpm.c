#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/config.h"
#include "../include/fpm.h"

extern Config config;

#define BUFFER_SIZE 4096

// Fungsi untuk mengenkode satu pasangan parameter (name-value)
void trim_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == '\t')) {
        str[len - 1] = '\0';
        len--;
    }
}

int add_pair(unsigned char* dest, const char *name, const char *value) {
    int name_len = strlen(name);
    char clean_value[256];
    int value_len;

    // Bersihkan buffer sebelum digunakan
    memset(clean_value, 0, sizeof(clean_value));

    // **Salin hanya panjang yang valid dari `value`**
    int actual_value_length = strlen(value);
    if (actual_value_length > sizeof(clean_value) - 1) {  
        actual_value_length = sizeof(clean_value) - 1;  // Pastikan tetap dalam batas buffer
    }
    memcpy(clean_value, value, actual_value_length);
    clean_value[actual_value_length] = '\0';  // Paksa null-terminate

    /*printf("FULL HEX DUMP OF clean_value BEFORE TRIM:\n");
    for (int i = 0; i < 30; i++) {  // Cetak 30 byte pertama dari buffer
        printf("%02X ", (unsigned char)clean_value[i]);
    }
    printf("\n");
    */
    // Bersihkan karakter tersembunyi
    trim_whitespace(clean_value);

    // **Gunakan strlen() setelah `trim()` untuk panjang yang benar**
    value_len = strlen(clean_value);
    
    /*printf("CHECK strlen(clean_value): %d\n", value_len);
    // Debugging panjang `value`
    printf("FINAL DEBUG: name='%s' (len=%d), value='%s' (len=%d)\n", name, name_len, clean_value, value_len);
    
    // Debugging hex dump
    printf("FINAL HEX DUMP value (after trim, correct length %d):\n", value_len);
    for (int i = 0; i < value_len; i++) {
        printf("%02X ", (unsigned char)clean_value[i]);
    }
    printf("\n");
    */

    int offset = 0;

    // Encode panjang name
    dest[offset++] = (unsigned char)name_len;

    // Encode panjang value
    dest[offset++] = (unsigned char)value_len;

    // Salin name dan value ke buffer
    memcpy(dest + offset, name, name_len);
    offset += name_len;
    memcpy(dest + offset, clean_value, value_len);
    offset += value_len;

    return offset;
}

void send_begin_request(int sockfd, int request_id) {
    // Kirim Begin Request
    FCGI_BeginRequestBody begin_request;
    begin_request.header.version = FCGI_VERSION_1;
    begin_request.header.type = FCGI_BEGIN_REQUEST;
    begin_request.header.requestIdB1 = request_id >> 8;
    begin_request.header.requestIdB0 = request_id & 0xFF;
    begin_request.header.contentLengthB1 = 0;
    begin_request.header.contentLengthB0 = 8;
    begin_request.header.paddingLength = 0;
    begin_request.header.reserved = 0;
    begin_request.roleB1 = 0;
    begin_request.roleB0 = FCGI_RESPONDER;
    begin_request.flags = 0;
    memset(begin_request.reserved, 0, sizeof(begin_request.reserved));
    send(sockfd, &begin_request, sizeof(begin_request), 0);

    // Debugging: Cetak data sebelum mengirim Begin Request
    /*printf("Sending FastCGI request (Begin Request):\n");
    for (size_t i = 0; i < sizeof(begin_request); i++) {
        printf("%02X ", ((unsigned char*)&begin_request)[i]);
    }
    printf("\n");*/
}

void send_params(int sockfd, int request_id, unsigned char *params, int params_len) {
    // Kirim blok parameter
    FCGI_Header params_header;
    params_header.version = FCGI_VERSION_1;
    params_header.type = FCGI_PARAMS;
    params_header.requestIdB1 = request_id >> 8;
    params_header.requestIdB0 = request_id & 0xFF;
    params_header.contentLengthB1 = (params_len >> 8) & 0xFF;
    params_header.contentLengthB0 = params_len & 0xFF;
    params_header.paddingLength = 0;
    params_header.reserved = 0;

    send(sockfd, &params_header, sizeof(params_header), 0);
    if (params_len > 0) {
        send(sockfd, params, params_len, 0);
    }

    // **PENTING:** Kirim `FCGI_PARAMS` kosong untuk menandakan akhir parameter
    params_header.contentLengthB1 = 0;
    params_header.contentLengthB0 = 0;
    send(sockfd, &params_header, sizeof(params_header), 0);

    /*printf("Sending FastCGI request (Params Header):\n");
    for (size_t i = 0; i < sizeof(params_header); i++) {
        printf("%02X ", ((unsigned char*)&params_header)[i]);
    }
    printf("\n");*/
}

void send_stdin(int sockfd, int request_id, const char *post_data, int post_data_len) {
    // ** Kirim FCGI_STDIN kosong untuk menandakan akhir request**
    FCGI_Header stdin_header;
    stdin_header.version = FCGI_VERSION_1;
    stdin_header.type = FCGI_STDIN;
    stdin_header.requestIdB1 = request_id >> 8;
    stdin_header.requestIdB0 = request_id & 0xFF;
    if (post_data_len > 0) {
        stdin_header.contentLengthB1 = (post_data_len >> 8) & 0xFF;
        stdin_header.contentLengthB0 = post_data_len & 0xFF;
    } else {
        stdin_header.contentLengthB1 = 0;
        stdin_header.contentLengthB0 = 0;
    }
    
    stdin_header.paddingLength = 0;
    stdin_header.reserved = 0;
    send(sockfd, &stdin_header, sizeof(stdin_header), 0);

    if (post_data_len > 0) {
        send(sockfd, post_data, post_data_len, 0);
    }

    /*printf("Sending FastCGI request (End of Request - FCGI_STDIN):\n");
    for (size_t i = 0; i < sizeof(stdin_header); i++) {
        printf("%02X ", ((unsigned char*)&stdin_header)[i]);
    }
    printf("\n");*/
}

void send_php_fpm_request(int sockfd, 
    const char *directory,
    const char *script_name, 
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    const char *content_type) {
    
    const char *document_root = config.document_root;
    int request_id = 1;
    //unsigned char buffer[BUFFER_SIZE];

    send_begin_request(sockfd, request_id);

    // Mempersiapkan blok parameter dengan enkoding yang benar
    int post_data_len = strlen(post_data);
    unsigned char params[BUFFER_SIZE];
    int params_len = 0;

    // Menggabungkan document_root dan script_name dengan benar
    char script_filename[BUFFER_SIZE];
    snprintf(script_filename, sizeof(script_filename), "%s%s/%s", document_root, directory, script_name);

    // Menggabungkan script_name dan query_string dengan benar untuk REQUEST_URI
    char request_uri[BUFFER_SIZE];
    if(strlen(query_string) > 0)
        snprintf(request_uri, sizeof(request_uri), "%s?%s", script_name, query_string);
    else if(strlen(path_info) > 0)
        snprintf(request_uri, sizeof(request_uri), "%s/%s", script_name, path_info);

    params_len += add_pair(params + params_len, "SCRIPT_FILENAME", script_filename);
    params_len += add_pair(params + params_len, "SCRIPT_NAME", script_name);  // Pastikan ini sesuai dengan skrip yang dijalankan
    params_len += add_pair(params + params_len, "REQUEST_METHOD", request_method);
    params_len += add_pair(params + params_len, "DOCUMENT_ROOT", document_root);
    params_len += add_pair(params + params_len, "QUERY_STRING", query_string);
    params_len += add_pair(params + params_len, "PATH_INFO", path_info);
    params_len += add_pair(params + params_len, "REQUEST_URI", request_uri);
    params_len += add_pair(params + params_len, "SERVER_PROTOCOL", "HTTP/1.1");
    params_len += add_pair(params + params_len, "GATEWAY_INTERFACE", "CGI/1.1");
    params_len += add_pair(params + params_len, "REMOTE_ADDR", "127.0.0.1");
    params_len += add_pair(params + params_len, "REMOTE_PORT", "12345");
    params_len += add_pair(params + params_len, "SERVER_SOFTWARE", "Halmos-FCGI");
    params_len += add_pair(params + params_len, "HTTP_HOST", "localhost");
    if(post_data_len > 0) {
        char post_data_len_str[10];  
        snprintf(post_data_len_str, sizeof(post_data_len_str), "%d", post_data_len);
        params_len += add_pair(params + params_len, "CONTENT_LENGTH", post_data_len_str);
        params_len += add_pair(params + params_len, "CONTENT_TYPE", content_type);
    }
    else {
        params_len += add_pair(params + params_len, "CONTENT_LENGTH", "0");
        params_len += add_pair(params + params_len, "CONTENT_TYPE", "");
    }

    // Kirim Parameter
    send_params(sockfd, request_id, params, params_len);

    //Kirim stdin
    send_stdin(sockfd, request_id, post_data, post_data_len);
}

Response_PHP_FPM receive_php_fpm_response(int sockfd) {
    char buffer[BUFFER_SIZE];  // Buffer untuk menerima data dari socket
    ssize_t received = 0;

    size_t total_size = 0;
    size_t buffer_capacity = BUFFER_SIZE;

    // Alokasi memori awal untuk menyimpan response body
    char *content_data = malloc(buffer_capacity);
    if (!content_data) {
        perror("Memory allocation failed");
        return (Response_PHP_FPM){NULL, NULL};
    }

    Response_PHP_FPM resData = {NULL, NULL};  // Variabel untuk menyimpan hasil

    int header_parsed = 0;
    char *header_end = NULL;
    //char *header_data = NULL;

    while ((received = recv(sockfd, buffer, BUFFER_SIZE, 0)) > 0) {
        size_t offset = 0;

        while (offset < received) {
            if (received - offset < 8) {  
                // Pastikan cukup data untuk header FastCGI
                break;
            }

            // Ambil informasi dari header FastCGI
            FCGI_Header *fcgi_header = (FCGI_Header *)(buffer + offset);
            size_t content_length = (fcgi_header->contentLengthB1 << 8) | fcgi_header->contentLengthB0;
            size_t total_length = 8 + content_length + fcgi_header->paddingLength;

            if (received - offset < total_length) {
                // Jika data belum lengkap, tunggu paket selanjutnya
                break;
            }

            // Ambil payload setelah 8-byte header FastCGI
            char *content_start = buffer + offset + 8;

            // **Pisahkan Header dan Body**
            if (!header_parsed) {
                header_end = strstr((char *)content_start, "\r\n\r\n");  // Cek header berakhir
                if (!header_end) {
                    header_end = strstr((char *)content_start, "\n\n"); // Cek jika pakai LF saja
                }

                if (header_end) {
                    header_parsed = 1;  // Tandai header sudah ditemukan
                    size_t header_size = header_end - (char *)content_start + 4; // \r\n\r\n panjang 4
                    
                    // **Simpan header dengan strdup()**
                    resData.header = malloc(header_size + 1);  // +1 untuk null-terminator
                    if (!resData.header) {
                        perror("Memory allocation failed");
                        return resData;
                    }

                    memcpy(resData.header, content_start, header_size);
                    resData.header[header_size] = '\0';  // Pastikan null-terminated
                    for (char *p = resData.header; *p; p++) {
                        if (*p == '\n' || *p == '\r') {
                            *p = ' ';  // Ubah newline dan carriage return jadi spasi
                        }
                    }
                    content_start = (char *)(header_end + 4); // Lompat ke body
                    content_length -= header_size;
                }
            }

            // **Perbesar buffer jika perlu**
            while (total_size + content_length >= buffer_capacity) {
                buffer_capacity *= 2;
                char *new_body_buffer = realloc(content_data, buffer_capacity);
                if (!new_body_buffer) {
                    perror("Realloc failed for body");
                    free(content_data);
                    free(resData.header);
                    return (Response_PHP_FPM){NULL, NULL};
                }
                content_data = new_body_buffer;
            }

            // **Simpan body ke buffer**
            memcpy(content_data + total_size, content_start, content_length);
            total_size += content_length;
            content_data[total_size] = '\0'; // Null-terminate

            offset += total_length;  // Lompat ke paket berikutnya
        }

        // Jika seluruh data sudah diterima, keluar dari loop
        if (received < BUFFER_SIZE) {
            break;
        }
    }

    // Jika tidak ada data yang diterima
    if (received <= 0) {
        free(content_data);
        free(resData.header);
        return (Response_PHP_FPM){NULL, NULL};
    }

    // **Simpan body dengan strdup()**
    resData.body = strdup(content_data);
    free(content_data); // Bebaskan buffer sementara

    return resData;  // Mengembalikan data header dan body
}

Response_PHP_FPM php_fpm_request(
    const char *directory, 
    const char *script_name, 
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    const char *content_type) {
    
    int sockfd;
    struct sockaddr_in server_addr;

    // Membuat socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        return (Response_PHP_FPM){NULL, NULL};
    }

    // Konfigurasi koneksi ke PHP-FPM (TCP pada port 9000)
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.port_fpm);
    inet_pton(AF_INET, config.server_fpm, &server_addr.sin_addr);

    // Menghubungkan ke PHP-FPM
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect error");
        close(sockfd);
        return (Response_PHP_FPM){NULL, NULL};
    }

    send_php_fpm_request(sockfd, 
        directory,
        script_name,
        request_method,
        query_string,
        path_info,
        post_data,
        content_type
    );
    
    Response_PHP_FPM response_fpm = receive_php_fpm_response(sockfd);
    close(sockfd);

    return response_fpm; // Mengembalikan response yang diterima
}

