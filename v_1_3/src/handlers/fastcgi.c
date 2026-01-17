#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h> 

#include "../include/protocols/common/http_utils.h"
#include "../include/core/config.h"
#include "../include/core/log.h"
#include "../include/handlers/fastcgi.h"

extern Config config;

#define BUFFER_SIZE 4096

#define MAX_RESPONSE_SIZE 52428800

const char* trim_header_value(const char* s) {
    if (!s) return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

int add_pair(unsigned char* dest, const char *name, const char *value, int current_offset, int max_len) {
    int name_len = strlen(name);
    char clean_value[1024]; 
    const char* val_ptr = value ? value : "";
    size_t actual_len = strlen(val_ptr);
    if (actual_len > sizeof(clean_value) - 1) actual_len = sizeof(clean_value) - 1;
    memcpy(clean_value, val_ptr, actual_len);
    clean_value[actual_len] = '\0';
    trim_whitespace(clean_value);
    int value_len = strlen(clean_value);

    if (current_offset + 2 + name_len + value_len > max_len) return 0;

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
    FCGI_BeginRequestBody begin_request;
    begin_request.header.version = FCGI_VERSION_1;
    begin_request.header.type = FCGI_BEGIN_REQUEST;
    begin_request.header.requestIdB1 = (request_id >> 8) & 0xFF;
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
}

void send_params(int sockfd, int request_id, unsigned char *params, int params_len) {
    int padding_len = (8 - (params_len % 8)) % 8;
    FCGI_Header params_header;
    params_header.version = FCGI_VERSION_1;
    params_header.type = FCGI_PARAMS;
    params_header.requestIdB1 = (request_id >> 8) & 0xFF;
    params_header.requestIdB0 = request_id & 0xFF;
    params_header.contentLengthB1 = (params_len >> 8) & 0xFF;
    params_header.contentLengthB0 = params_len & 0xFF;
    params_header.paddingLength = padding_len;
    params_header.reserved = 0;

    send(sockfd, &params_header, sizeof(params_header), 0);
    if (params_len > 0) send(sockfd, params, params_len, 0);
    if (padding_len > 0) {
        unsigned char padding[8] = {0};
        send(sockfd, padding, padding_len, 0);
    }

    params_header.contentLengthB1 = 0;
    params_header.contentLengthB0 = 0;
    params_header.paddingLength = 0;
    send(sockfd, &params_header, sizeof(params_header), 0);
}

void send_stdin(int sockfd, int request_id, const void *post_data, int post_data_len) {
    printf("\n[DEBUG STDIN] --- START CHUNKING SEND_STDIN ---\n");
    printf("[DEBUG STDIN] Total Data to Send: %d bytes\n", post_data_len);

    int sent_so_far = 0;
    while (sent_so_far < post_data_len) {
        // Tentukan besar chunk (maksimal 65535)
        int chunk_size = post_data_len - sent_so_far;
        if (chunk_size > 65535) chunk_size = 65535;

        int padding_len = (8 - (chunk_size % 8)) % 8;

        FCGI_Header stdin_header;
        stdin_header.version = FCGI_VERSION_1;
        stdin_header.type = 5; // STDIN
        stdin_header.requestIdB1 = (request_id >> 8) & 0xFF;
        stdin_header.requestIdB0 = request_id & 0xFF;
        stdin_header.contentLengthB1 = (chunk_size >> 8) & 0xFF;
        stdin_header.contentLengthB0 = chunk_size & 0xFF;
        stdin_header.paddingLength = padding_len;
        stdin_header.reserved = 0;

        // 1. Kirim Header untuk chunk ini
        send(sockfd, &stdin_header, 8, 0);
        
        // 2. Kirim potongan data biner
        send(sockfd, post_data + sent_so_far, chunk_size, 0);
        
        // 3. Kirim padding jika ada
        if (padding_len > 0) {
            unsigned char padding[8] = {0};
            send(sockfd, padding, padding_len, 0);
        }

        sent_so_far += chunk_size;
        printf("[DEBUG STDIN] Sent chunk: %d bytes. Progress: %d/%d\n", chunk_size, sent_so_far, post_data_len);
    }

    // WAJIB: Kirim paket STDIN kosong (EOF) setelah semua chunk habis
    FCGI_Header empty_stdin = {0};
    empty_stdin.version = FCGI_VERSION_1;
    empty_stdin.type = 5;
    empty_stdin.requestIdB1 = (request_id >> 8) & 0xFF;
    empty_stdin.requestIdB0 = request_id & 0xFF;
    send(sockfd, &empty_stdin, 8, 0);
    
    printf("[DEBUG STDIN] --- ALL CHUNKS SENT ---\n\n");
}

void send_generic_fcgi_payload(int sockfd,
    const char *directory,
    const char *script_name,
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    size_t post_data_len,
    const char *content_type) {
    
    const char *document_root = config.document_root;
    int request_id = 1;

    send_begin_request(sockfd, request_id);

    unsigned char params[BUFFER_SIZE];
    int params_len = 0;

    char script_filename[BUFFER_SIZE];
    snprintf(script_filename, sizeof(script_filename), "%s/%s/%s", document_root, directory, script_name);

    char clean_filename[BUFFER_SIZE];
    int j = 0;
    for (int i = 0; script_filename[i] != '\0' && j < BUFFER_SIZE - 1; i++) {
        if (script_filename[i] == '/' && script_filename[i+1] == '/') continue;
        clean_filename[j++] = script_filename[i];
    }
    clean_filename[j] = '\0';

    char request_uri[BUFFER_SIZE];
    if(query_string && strlen(query_string) > 0) 
        snprintf(request_uri, sizeof(request_uri), "%s?%s", script_name, query_string);
    else 
        snprintf(request_uri, sizeof(request_uri), "%s", script_name);

    params_len += add_pair(params + params_len, "SCRIPT_FILENAME", clean_filename, params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "SCRIPT_NAME", script_name, params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "REQUEST_METHOD", request_method, params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "DOCUMENT_ROOT", document_root, params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "QUERY_STRING", query_string ? query_string : "", params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "REQUEST_URI", request_uri, params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "SERVER_PROTOCOL", "HTTP/1.1", params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "GATEWAY_INTERFACE", "CGI/1.1", params_len, BUFFER_SIZE);
    params_len += add_pair(params + params_len, "REDIRECT_STATUS", "200", params_len, BUFFER_SIZE);

    if(post_data_len > 0) {
        char post_len_str[16];
        snprintf(post_len_str, sizeof(post_len_str), "%zu", post_data_len);
        printf("[DEBUG PARAMS] --- CONTENT METADATA ---\n");
        printf("[DEBUG PARAMS] CONTENT_LENGTH promised to PHP: %s\n", post_len_str);
        printf("[DEBUG PARAMS] CONTENT_TYPE: %s\n", content_type);
        params_len += add_pair(params + params_len, "CONTENT_LENGTH", post_len_str, params_len, BUFFER_SIZE);
        params_len += add_pair(params + params_len, "CONTENT_TYPE", trim_header_value(content_type), params_len, BUFFER_SIZE);
    }

    send_params(sockfd, request_id, params, params_len);
    send_stdin(sockfd, request_id, post_data, (int)post_data_len);
}

FastCGI_Response fcgi_response(int sockfd) {
    FastCGI_Response resData = {NULL, NULL};
    char *full_payload = NULL;
    size_t total_payload_size = 0;
    unsigned char header_buf[8];
    int keep_reading = 1;

    while (keep_reading) {
        ssize_t h_rec = recv(sockfd, header_buf, 8, MSG_WAITALL);
        if (h_rec < 8) break;
        FCGI_Header *h = (FCGI_Header *)header_buf;
        int content_len = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int padding_len = h->paddingLength;

        if (content_len + padding_len > 0) {
            unsigned char *content = malloc(content_len + padding_len);
            recv(sockfd, content, content_len + padding_len, MSG_WAITALL);
            if (h->type == 6) { 
                char *new_ptr = realloc(full_payload, total_payload_size + content_len + 1);
                if (new_ptr) {
                    full_payload = new_ptr;
                    memcpy(full_payload + total_payload_size, content, content_len);
                    total_payload_size += content_len;
                    full_payload[total_payload_size] = '\0';
                }
            }
            free(content);
        }
        if (h->type == 3) keep_reading = 0;
    }

    if (full_payload) {
        char *delim = strstr(full_payload, "\r\n\r\n");
        if (delim) {
            *delim = '\0';
            resData.header = strdup(full_payload);
            resData.body = strdup(delim + 4);
        } else {
            resData.body = strdup(full_payload);
        }
        free(full_payload);
    }
    return resData;
}

FastCGI_Response fastcgi_request(
    const char *target_ip,
    int target_port,
    const char *directory,
    const char *script_name,
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    size_t post_data_len, 
    const char *content_type) {
    
    int sockfd;
    struct sockaddr_in server_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return (FastCGI_Response){NULL, NULL};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return (FastCGI_Response){NULL, NULL};
    }

    send_generic_fcgi_payload(sockfd, directory, script_name, request_method, 
                             query_string, path_info, post_data, post_data_len, content_type);
    
    FastCGI_Response response_fpm = fcgi_response(sockfd);
    close(sockfd);
    return response_fpm;
}

FastCGI_Response cgi_request_stream(
    const char *target_ip,
    int target_port,
    int sock_client,          // Ditambahkan supaya bisa recv() sisa body
    const char *method,        // Diubah dari array[8] ke pointer biar fleksibel
    const char *script_name,
    const char *query_string,
    void *post_data,          // Data awal dari parser
    size_t post_data_len,     // Panjang data awal
    size_t content_length,     // Total Content-Length dari Header HTTP
    const char *content_type) {
    
    FastCGI_Response res = {NULL, NULL};
    int request_id = 1;

    // A. Koneksi ke Backend
    int fpm_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in fpm_addr;
    memset(&fpm_addr, 0, sizeof(fpm_addr));
    fpm_addr.sin_family = AF_INET;
    fpm_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &fpm_addr.sin_addr);

    if (connect(fpm_sock, (struct sockaddr *)&fpm_addr, sizeof(fpm_addr)) < 0) {
        // Gunakan fprintf kalau write_log belum ter-include
        printf("[ERROR] Backend Down at %s:%d\n", target_ip, target_port);
        return res; 
    }

    // B. Kirim BEGIN_REQUEST & PARAMS
    send_begin_request(fpm_sock, request_id);
    
    unsigned char params_buf[BUFFER_SIZE];
    int p_len = 0;
    
    // Sesuaikan path file
    char script_filename[1024];
    snprintf(script_filename, sizeof(script_filename), "%s/%s", config.document_root, script_name);

    // Format Content-Length string
    char cl_str[20];
    snprintf(cl_str, sizeof(cl_str), "%zu", content_length);

    // Sanitize Content-Type
    const char *clean_ct = content_type ? content_type : "";
    while(*clean_ct == ' ') clean_ct++; 

    // Isi Params (PASTIKAN add_pair kamu support urutan ini)
    p_len += add_pair(params_buf + p_len, "SCRIPT_FILENAME", script_filename, p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "REQUEST_METHOD", method, p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "CONTENT_LENGTH", cl_str, p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "CONTENT_TYPE", clean_ct, p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "QUERY_STRING", query_string ? query_string : "", p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "REQUEST_URI", script_name, p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "SERVER_PROTOCOL", "HTTP/1.1", p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "GATEWAY_INTERFACE", "CGI/1.1", p_len, BUFFER_SIZE);
    p_len += add_pair(params_buf + p_len, "REDIRECT_STATUS", "200", p_len, BUFFER_SIZE);

    send_params(fpm_sock, request_id, params_buf, p_len);

    // C. PROSES STREAMING BODY
    size_t total_streamed = 0;

    // 1. Kirim sisa data yang sudah "nyangkut" di parser Halmos
    if (post_data_len > 0 && post_data != NULL) {
        send_stdin(fpm_sock, request_id, post_data, (int)post_data_len);
        total_streamed += post_data_len;
    }

    // 2. Baca sisanya langsung dari socket client dan "tembak" ke FPM
    if (sock_client != -1 && total_streamed < content_length) {
        char stream_buffer[16384]; 
        while (total_streamed < content_length) {
            ssize_t n = recv(sock_client, stream_buffer, sizeof(stream_buffer), 0);
            if (n <= 0) break; 
            
            send_stdin(fpm_sock, request_id, stream_buffer, (int)n);
            total_streamed += n;
        }
    }

    // D. WAJIB: Kirim STDIN Kosong sebagai tanda SELESAI
    send_stdin(fpm_sock, request_id, NULL, 0);

    // E. Terima Balasan
    res = fcgi_response(fpm_sock);
    
    close(fpm_sock);
    return res;
}
