#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h> // Pastikan header ini ada di bagian atas fpm.c

#include "../include/protocols/common/http_utils.h"
#include "../include/core/config.h"
#include "../include/core/log.h"
#include "../include/handlers/fastcgi.h"

extern Config config;

#define BUFFER_SIZE 4096

int add_pair(unsigned char* dest, const char *name, const char *value, int current_offset, int max_len) {
    int name_len = strlen(name);
    
    // Gunakan buffer sementara untuk membersihkan value
    char clean_value[1024]; // Batasi panjang value agar tidak overflow di stack
    size_t actual_len = strlen(value);
    if (actual_len > sizeof(clean_value) - 1) actual_len = sizeof(clean_value) - 1;
    
    memcpy(clean_value, value, actual_len);
    clean_value[actual_len] = '\0';
    trim_whitespace(clean_value);
    
    int value_len = strlen(clean_value);

    // --- PROTEKSI OVERFLOW ---
    // Header (2 byte) + Name + Value harus muat di sisa buffer
    if (current_offset + 2 + name_len + value_len > max_len) {
        write_log("Security: FastCGI Params buffer exceeded! Truncating.");
        return 0; // Berhenti menambah jika tidak muat
    }

    int offset = 0;
    dest[offset++] = (unsigned char)name_len;
    dest[offset++] = (unsigned char)value_len;

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
    // 1. Hitung Padding agar total data habis dibagi 8
    int padding_len = (8 - (params_len % 8)) % 8;

    FCGI_Header params_header;
    params_header.version = FCGI_VERSION_1;
    params_header.type = FCGI_PARAMS;
    params_header.requestIdB1 = request_id >> 8;
    params_header.requestIdB0 = request_id & 0xFF;
    params_header.contentLengthB1 = (params_len >> 8) & 0xFF;
    params_header.contentLengthB0 = params_len & 0xFF;
    params_header.paddingLength = padding_len; // <--- ISI INI
    params_header.reserved = 0;

    // Kirim Header
    send(sockfd, &params_header, sizeof(params_header), 0);
    
    // Kirim Body (Params)
    if (params_len > 0) {
        send(sockfd, params, params_len, 0);
    }

    // Kirim Padding (Isinya bebas, biasanya 0)
    if (padding_len > 0) {
        unsigned char padding[8] = {0};
        send(sockfd, padding, padding_len, 0);
    }

    // 2. Kirim FCGI_PARAMS kosong (End of Params)
    // Ingat: Header kosong ini panjangnya 0, jadi paddingnya juga 0.
    params_header.contentLengthB1 = 0;
    params_header.contentLengthB0 = 0;
    params_header.paddingLength = 0; 
    send(sockfd, &params_header, sizeof(params_header), 0);
}

void send_stdin(int sockfd, int request_id, const char *post_data, int post_data_len) {
    FCGI_Header stdin_header;
    stdin_header.version = FCGI_VERSION_1;
    stdin_header.type = FCGI_STDIN;
    stdin_header.requestIdB1 = request_id >> 8;
    stdin_header.requestIdB0 = request_id & 0xFF;
    stdin_header.paddingLength = 0;
    stdin_header.reserved = 0;

    // 1. Jika ada data POST, kirim datanya dulu
    if (post_data_len > 0) {
        stdin_header.contentLengthB1 = (post_data_len >> 8) & 0xFF;
        stdin_header.contentLengthB0 = post_data_len & 0xFF;
        send(sockfd, &stdin_header, sizeof(stdin_header), 0);
        send(sockfd, post_data, post_data_len, 0);
    }

    // 2. WAJIB: Kirim paket STDIN KOSONG (Length 0)
    // Ini adalah sinyal mutlak bagi Rust bahwa stream STDIN sudah berakhir
    stdin_header.contentLengthB1 = 0;
    stdin_header.contentLengthB0 = 0;
    send(sockfd, &stdin_header, sizeof(stdin_header), 0);
}

void send_generic_fcgi_payload(int sockfd, 
    const char *directory,
    const char *script_name, 
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    const char *content_type) {
    
    const char *document_root = config.document_root;
    int request_id = 1;

    send_begin_request(sockfd, request_id);

    // Mempersiapkan blok parameter dengan enkoding yang benar
    int post_data_len = strlen(post_data);
    unsigned char params[BUFFER_SIZE];
    int params_len = 0;

    // Menggabungkan document_root dan script_name dengan benar
    // --- PERBAIKAN LOGIKA PATH ---
    char script_filename[BUFFER_SIZE];
    
    // Jika script_name dimulai dengan '/', artinya itu kemungkinan sudah path absolut
    // atau hasil sanitasi yang sudah termasuk document_root.
    if (script_name[0] == '/') {
        // Cek apakah script_name sudah mengandung document_root di dalamnya
        if (strstr(script_name, document_root) != NULL) {
            // Jika sudah ada document_root, gunakan script_name langsung
            snprintf(script_filename, sizeof(script_filename), "%s", script_name);
        } else {
            // Jika belum, gabungkan document_root dengan script_name tanpa slash tambahan
            snprintf(script_filename, sizeof(script_filename), "%s%s", document_root, script_name);
        }
    } else {
        // Jika script_name adalah path relatif, gabungkan normal
        snprintf(script_filename, sizeof(script_filename), "%s/%s", document_root, script_name);
    }

    // Pembersihan Akhir: Menghilangkan double/triple slash yang tersisa
    char clean_filename[BUFFER_SIZE];
    int j = 0;
    for (int i = 0; script_filename[i] != '\0' && j < BUFFER_SIZE - 1; i++) {
        if (script_filename[i] == '/' && script_filename[i+1] == '/') {
            continue; // Lewati slash jika karakter berikutnya juga slash
        }
        clean_filename[j++] = script_filename[i];
    }
    clean_filename[j] = '\0';
    // --- END PERBAIKAN ---

    printf("DEBUG: Mengirim SCRIPT_FILENAME ke Backend: [%s]\n", clean_filename);

    // Menggabungkan script_name dan query_string dengan benar untuk REQUEST_URI
    char request_uri[BUFFER_SIZE];
    if(strlen(query_string) > 0)
        snprintf(request_uri, sizeof(request_uri), "%s?%s", script_name, query_string);
    else if(strlen(path_info) > 0)
        snprintf(request_uri, sizeof(request_uri), "%s/%s", script_name, path_info);

    int n = add_pair(params + params_len, "SCRIPT_FILENAME", clean_filename, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "SCRIPT_NAME", script_name, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "REQUEST_METHOD", request_method, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "DOCUMENT_ROOT", document_root, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "QUERY_STRING", query_string, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "PATH_INFO", path_info, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "REQUEST_URI", request_uri, params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "SERVER_PROTOCOL", "HTTP/1.1", params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "GATEWAY_INTERFACE", "CGI/1.1", params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "REMOTE_ADDR", "127.0.0.1", params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "REMOTE_PORT", "12345", params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "SERVER_SOFTWARE", "Halmos-FCGI", params_len, BUFFER_SIZE);
    params_len += n;

    n = add_pair(params + params_len, "HTTP_HOST", "localhost", params_len, BUFFER_SIZE);
    params_len += n;

    if(post_data_len > 0) {
        char post_data_len_str[10];  
        snprintf(post_data_len_str, sizeof(post_data_len_str), "%d", post_data_len);
        
        n = add_pair(params + params_len, "CONTENT_LENGTH", post_data_len_str, params_len, BUFFER_SIZE);
        params_len += n;
        
        n = add_pair(params + params_len, "CONTENT_TYPE", content_type, params_len, BUFFER_SIZE);
        params_len += n;
    }
    else {
        n = add_pair(params + params_len, "CONTENT_LENGTH", "0", params_len, BUFFER_SIZE);
        params_len += n;
        
        n = add_pair(params + params_len, "CONTENT_TYPE", "", params_len, BUFFER_SIZE);
        params_len += n;
    }

    // Kirim Parameter
    send_params(sockfd, request_id, params, params_len);

    //Kirim stdin
    send_stdin(sockfd, request_id, post_data, post_data_len);
}

FastCGI_Response receive_fcgi_response(int sockfd) {
    FastCGI_Response resData = {NULL, NULL};
    char *full_payload = NULL;
    size_t total_payload_size = 0;
    
    unsigned char header_buf[8];
    int keep_reading = 1;

    while (keep_reading) {
        // 1. Baca Header (8 Byte)
        ssize_t h_rec = recv(sockfd, header_buf, 8, MSG_WAITALL);
        if (h_rec < 8) break;

        FCGI_Header *h = (FCGI_Header *)header_buf;
        int content_len = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int padding_len = h->paddingLength;

        // 2. Baca Konten (STDOUT / STDERR)
        if (content_len + padding_len > 0) {
            unsigned char *content = malloc(content_len + padding_len);
            if (!content) break; // Error alokasi

            recv(sockfd, content, content_len + padding_len, MSG_WAITALL);

            if (h->type == 6) { // FCGI_STDOUT (Data dari PHP/Rust)
                char *new_ptr = realloc(full_payload, total_payload_size + content_len + 1);
                if (new_ptr) {
                    full_payload = new_ptr;
                    memcpy(full_payload + total_payload_size, content, content_len);
                    total_payload_size += content_len;
                    full_payload[total_payload_size] = '\0';
                }
            } 
            else if (h->type == 7) { // FCGI_STDERR (Log error)
                write_log("FastCGI Backend Error: %.*s", content_len, content);
            }
            free(content);
        }

        if (h->type == 3) { // FCGI_END_REQUEST
            keep_reading = 0;
        }
    }

    // --- PERBAIKAN MANAJEMEN MEMORI DI SINI ---
    if (full_payload) {
        // Cari pembatas antara Header HTTP dan Body (\r\n\r\n)
        char *delim = strstr(full_payload, "\r\n\r\n");
        if (delim) {
            // Gunakan teknik "in-place termination" untuk efisiensi
            *delim = '\0'; 
            
            // Sekarang full_payload berisi Header saja
            resData.header = strdup(full_payload);
            
            // delim + 4 adalah awal dari Body
            resData.body = strdup(delim + 4);
        } else {
            // Jika tidak ada header (langsung body)
            resData.body = strdup(full_payload);
        }
        
        // Bebaskan buffer sementara setelah data disalin ke resData
        free(full_payload);
    }

    return resData;
}

FastCGI_Response fastcgi_request(
    const char *target_ip,   // Parameter baru
    int target_port,         // Parameter baru
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
        return (FastCGI_Response){NULL, NULL};
    }

    // Tambahkan ini setelah socket() di php_fpm_request
    struct timeval timeout;
    timeout.tv_sec = 30; // 30 detik timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Konfigurasi koneksi ke PHP-FPM (TCP pada port 9000)
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Menghubungkan ke PHP-FPM
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect error");
        close(sockfd);
        return (FastCGI_Response){NULL, NULL};
    }

    send_generic_fcgi_payload(sockfd, 
        directory,
        script_name,
        request_method,
        query_string,
        path_info,
        post_data,
        content_type
    );
    
    FastCGI_Response response_fpm = receive_fcgi_response(sockfd);
    close(sockfd);

    return response_fpm; // Mengembalikan response yang diterima
}

