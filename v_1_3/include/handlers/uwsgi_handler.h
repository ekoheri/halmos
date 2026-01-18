#ifndef UWSGI_HANDLER_H
#define UWSGI_HANDLER_H

#include <stddef.h>

// Gunakan struct yang sama dengan FastCGI agar konsisten di core logic-mu
typedef struct {
    char *header;
    char *body;
    size_t body_len;
} UWSGI_Response;

// Fungsi Utama
UWSGI_Response uwsgi_request_stream(
    const char *target_ip,
    int target_port,
    int sock_client,          
    const char *method,        
    const char *script_name,
    const char *query_string,
    void *post_data,          
    size_t post_data_len,     
    size_t content_length,     
    const char *content_type
);

// Helper untuk membersihkan memory
void free_uwsgi_response(UWSGI_Response *res);
UWSGI_Response uwsgi_request_stream(
    const char *target_ip, int target_port, int sock_client,
    const char *method, const char *script_name, const char *query_string,
    void *post_data, size_t post_data_len, size_t content_length, const char *content_type);

#endif