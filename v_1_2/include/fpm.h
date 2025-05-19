#ifndef FPM_H
#define FPM_H

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
} Response_PHP_FPM;

Response_PHP_FPM php_fpm_request(
    const char *directory, 
    const char *script_name, 
    const char request_method[8],
    const char *query_string,
    const char *path_info,
    const char *post_data,
    const char *content_type);

#endif