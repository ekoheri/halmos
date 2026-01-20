#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h> 
#include <threads.h> // Untuk thread_local

#include "http_utils.h"
#include "config.h"
#include "log.h"
#include "fastcgi.h"

extern Config config;

const char* trim_header_value(const char* s) {
    if (!s) return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

int add_pair(unsigned char* dest, const char *name, const char *value, int current_offset, int max_len) {
    int name_len = (int)strlen(name);
    const char* val_ptr = value ? value : "";
    int value_len = (int)strlen(val_ptr);

    int name_len_bytes = (name_len > 127) ? 4 : 1;
    int value_len_bytes = (value_len > 127) ? 4 : 1;

    if (current_offset + name_len_bytes + value_len_bytes + name_len + value_len > max_len) {
        return 0; 
    }

    int offset = current_offset;
    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)name_len;
    }

    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)value_len;
    }

    memcpy(dest + offset, name, name_len);
    offset += name_len;
    memcpy(dest + offset, val_ptr, value_len);
    offset += value_len;

    return (offset - current_offset);
}

// UPDATE: Ditambah parameter flags (0 atau 1)
void send_begin_request(int sockfd, int request_id, int keep_conn) {
    FCGI_BeginRequestBody begin_request;
    memset(&begin_request, 0, sizeof(begin_request));
    begin_request.header.version = FCGI_VERSION_1;
    begin_request.header.type = FCGI_BEGIN_REQUEST;
    begin_request.header.requestIdB1 = (request_id >> 8) & 0xFF;
    begin_request.header.requestIdB0 = request_id & 0xFF;
    begin_request.header.contentLengthB1 = 0;
    begin_request.header.contentLengthB0 = 8;
    
    begin_request.roleB1 = 0;
    begin_request.roleB0 = FCGI_RESPONDER;
    // SET FLAG KEEP_CONN DISINI
    begin_request.flags = keep_conn ? FCGI_KEEP_CONN : 0;
    
    send(sockfd, &begin_request, sizeof(begin_request), 0);
}

void send_params(int sockfd, int request_id, unsigned char *params, int params_len) {
    int padding_len = (8 - (params_len % 8)) % 8;
    FCGI_Header params_header;
    memset(&params_header, 0, sizeof(params_header));
    params_header.version = FCGI_VERSION_1;
    params_header.type = FCGI_PARAMS;
    params_header.requestIdB1 = (request_id >> 8) & 0xFF;
    params_header.requestIdB0 = request_id & 0xFF;
    params_header.contentLengthB1 = (params_len >> 8) & 0xFF;
    params_header.contentLengthB0 = params_len & 0xFF;
    params_header.paddingLength = padding_len;

    send(sockfd, &params_header, sizeof(params_header), 0);
    if (params_len > 0) send(sockfd, params, params_len, 0);
    if (padding_len > 0) {
        unsigned char padding[8] = {0};
        send(sockfd, padding, padding_len, 0);
    }

    // End of Params
    params_header.contentLengthB1 = 0;
    params_header.contentLengthB0 = 0;
    params_header.paddingLength = 0;
    send(sockfd, &params_header, sizeof(params_header), 0);
}

void send_stdin(int sockfd, int request_id, const void *post_data, int post_data_len) {
    int sent_so_far = 0;
    if (post_data_len > 0 && post_data != NULL) {
        while (sent_so_far < post_data_len) {
            int chunk_size = post_data_len - sent_so_far;
            if (chunk_size > 65535) chunk_size = 65535;
            int padding_len = (8 - (chunk_size % 8)) % 8;

            FCGI_Header stdin_header;
            memset(&stdin_header, 0, sizeof(stdin_header));
            stdin_header.version = FCGI_VERSION_1;
            stdin_header.type = FCGI_STDIN;
            stdin_header.requestIdB1 = (request_id >> 8) & 0xFF;
            stdin_header.requestIdB0 = request_id & 0xFF;
            stdin_header.contentLengthB1 = (chunk_size >> 8) & 0xFF;
            stdin_header.contentLengthB0 = chunk_size & 0xFF;
            stdin_header.paddingLength = padding_len;

            send(sockfd, &stdin_header, 8, 0);
            send(sockfd, (char*)post_data + sent_so_far, chunk_size, 0);
            if (padding_len > 0) {
                unsigned char padding[8] = {0};
                send(sockfd, padding, padding_len, 0);
            }
            sent_so_far += chunk_size;
        }
    }

    FCGI_Header empty_stdin;
    memset(&empty_stdin, 0, sizeof(empty_stdin));
    empty_stdin.version = FCGI_VERSION_1;
    empty_stdin.type = FCGI_STDIN;
    empty_stdin.requestIdB1 = (request_id >> 8) & 0xFF;
    empty_stdin.requestIdB0 = request_id & 0xFF;
    send(sockfd, &empty_stdin, 8, 0);
}

FastCGI_Response fcgi_response(int sockfd) {
    FastCGI_Response resData = {NULL, NULL};
    char *full_payload = NULL;
    size_t total_payload_size = 0;
    unsigned char header_buf[8];
    int keep_reading = 1;

    while (keep_reading) {
        ssize_t h_rec = recv(sockfd, header_buf, 8, MSG_WAITALL);
        if (h_rec <= 0) {
            // Socket terputus oleh backend
            break;
        }
        
        FCGI_Header *h = (FCGI_Header *)header_buf;
        int content_len = (h->contentLengthB1 << 8) | h->contentLengthB0;
        int padding_len = h->paddingLength;

        if (content_len + padding_len > 0) {
            unsigned char *content = malloc(content_len + padding_len);
            if (recv(sockfd, content, content_len + padding_len, MSG_WAITALL) <= 0) {
                free(content);
                break;
            }
            if (h->type == FCGI_STDOUT) { 
                char *new_ptr = realloc(full_payload, total_payload_size + content_len + 1);
                if (new_ptr) {
                    full_payload = new_ptr;
                    memcpy(full_payload + total_payload_size, content, content_len);
                    total_payload_size += content_len;
                    full_payload[total_payload_size] = '\0';
                }
            }
            // Jika tipenya END_REQUEST (3), kita sudah baca payload-nya di atas, 
            // sekarang saatnya berhenti tanpa perlu recv lagi.
            if (h->type == FCGI_END_REQUEST) {
                keep_reading = 0;
            }
            free(content);
        } else {
            // Kalau ada paket tanpa konten tapi tipenya END_REQUEST
            if (h->type == FCGI_END_REQUEST) keep_reading = 0;
        }
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

// LOGIKA POOLING PER THREAD
// Gunakan _Thread_local agar setiap thread punya socket masing-masing
static _Thread_local int cached_fpm_sock = -1;

FastCGI_Response cgi_request_stream(
    const char *target_ip,
    int target_port,
    int sock_client,          
    const char *method,        
    const char *script_name,
    const char *query_string,
    void *post_data,          
    size_t post_data_len,     
    size_t content_length,     
    const char *content_type,
    const char *cookie_data) {
    
    FastCGI_Response res = {NULL, NULL};
    int request_id = 1;

    // 1. Ambil socket dari cache atau buat baru
    int fpm_sock = cached_fpm_sock;
    
    // Validasi apakah socket masih hidup
    if (fpm_sock != -1) {
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(fpm_sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            close(fpm_sock);
            fpm_sock = -1;
        }
    }

    if (fpm_sock == -1) {
        fpm_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in fpm_addr;
        memset(&fpm_addr, 0, sizeof(fpm_addr));
        fpm_addr.sin_family = AF_INET;
        fpm_addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip, &fpm_addr.sin_addr);

        if (connect(fpm_sock, (struct sockaddr *)&fpm_addr, sizeof(fpm_addr)) < 0) {
            close(fpm_sock);
            return res; 
        }
        cached_fpm_sock = fpm_sock; // Simpan ke cache
    }

    // 2. Kirim BEGIN_REQUEST dengan KEEP_CONN (flag=1)
    send_begin_request(fpm_sock, request_id, 1);

    unsigned char params_buf[16384]; 
    int p_len = 0;
    int written = 0;
    
    #define PUSH_PARAM(name, val) \
        written = add_pair(params_buf, name, val, p_len, sizeof(params_buf)); \
        if (written > 0) p_len += written; \
        else write_log("[FCGI] Warning: Buffer full, skipped %s", name);
    
    char script_filename[1024];
    snprintf(script_filename, sizeof(script_filename), "%s/%s", config.document_root, script_name);

    char cl_str[20];
    snprintf(cl_str, sizeof(cl_str), "%zu", content_length);

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_size) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    PUSH_PARAM("SCRIPT_FILENAME", script_filename);
    PUSH_PARAM("REQUEST_METHOD", method);
    PUSH_PARAM("QUERY_STRING", query_string ? query_string : "");
    
    const char *sanitized_ct = trim_header_value(content_type);
    if (strcmp(method, "POST") == 0) {
        PUSH_PARAM("CONTENT_LENGTH", cl_str);
        PUSH_PARAM("CONTENT_TYPE", (sanitized_ct && strlen(sanitized_ct) > 0) ? sanitized_ct : "application/x-www-form-urlencoded");
    } else {
        PUSH_PARAM("CONTENT_LENGTH", "0");
        PUSH_PARAM("CONTENT_TYPE", "");
    }

    PUSH_PARAM("SERVER_SOFTWARE", "Halmos-Core/1.3");
    PUSH_PARAM("SERVER_NAME", config.server_name);
    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", config.server_port);
    PUSH_PARAM("SERVER_PORT", port_str);
    PUSH_PARAM("DOCUMENT_ROOT", config.document_root);
    PUSH_PARAM("REQUEST_URI", script_name);
    PUSH_PARAM("SCRIPT_NAME", script_name);
    PUSH_PARAM("SERVER_PROTOCOL", "HTTP/1.1");
    PUSH_PARAM("GATEWAY_INTERFACE", "CGI/1.1");
    PUSH_PARAM("REMOTE_ADDR", client_ip);
    PUSH_PARAM("REDIRECT_STATUS", "200");

    if (cookie_data) {
        PUSH_PARAM("HTTP_COOKIE", cookie_data);
    }

    send_params(fpm_sock, request_id, params_buf, p_len);

    // 7. STREAMING BODY
    size_t total_streamed = 0;
    if (post_data_len > 0 && post_data != NULL) {
        send_stdin(fpm_sock, request_id, post_data, (int)post_data_len);
        total_streamed += post_data_len;
    }

    if (sock_client != -1 && total_streamed < content_length) {
        char stream_buffer[16384]; 
        while (total_streamed < content_length) {
            ssize_t n = recv(sock_client, stream_buffer, sizeof(stream_buffer), 0);
            if (n > 0) {
                send_stdin(fpm_sock, request_id, stream_buffer, (int)n);
                total_streamed += n;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                usleep(100); 
                continue; 
            } else {
                break; 
            }
        }
    }

    send_stdin(fpm_sock, request_id, NULL, 0);

    // 9. Terima Balasan
    res = fcgi_response(fpm_sock);
    
    // JANGAN DI-CLOSE! Cukup reset cache kalau error.
    if (res.body == NULL && res.header == NULL) {
        close(fpm_sock);
        cached_fpm_sock = -1;
    }

    return res;
}