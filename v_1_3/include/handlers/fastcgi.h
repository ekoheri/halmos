#ifndef FASTCGI_H
#define FASTCGI_H

#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_PARAMS 4
#define FCGI_RESPONDER 1
#define FCGI_STDIN 5

// Struktur header FastCGI
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

// Struktur untuk permintaan Begin Request FastCGI
typedef struct {
    FCGI_Header header;
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    char *header;
    char *body;
} FastCGI_Response;

FastCGI_Response fastcgi_request(
    const char *target_ip,
    int target_port,
    const char *directory, 
    const char *script_name, 
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    size_t post_data_len,     // Argumen ke-9
    const char *content_type  // Argumen ke-10
);

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
    const char *content_type
);

#endif