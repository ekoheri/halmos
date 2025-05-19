#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <regex.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// Tambahan library untuk kompresi
#include <brotli/encode.h>
#include <brotli/decode.h>

#include "../include/http.h"
#include "../include/config.h"
#include "../include/log.h"
#include "../include/sha256.h"
#include "../include/chacha20.h"
#include "../include/pasaran.h"
#include "../include/brotli_comp.h"
#include "../include/bs64.h"
#include "../include/libutils.h"
#include "../include/fpm.h"

#define BUFFER_SIZE 1024

extern Config config;

int request_buffer_size = BUFFER_SIZE * 4;
int response_buffer_size = BUFFER_SIZE * 8;

//Fungsi untuk menormanilasi input base64
void sanitize_base64_input(char *str) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src != '\r' && *src != '\n') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

// Fungsi untuk mengonversi hex menjadi karakter
char hex_to_char(char first, char second) {
    char hex[3] = {first, second, '\0'};
    return (char) strtol(hex, NULL, 16);
}

// Fungsi URL decoding
void url_decode(const char *src, char *dest) {
    while (*src) {
        if (*src == '%') {
            if (isxdigit(src[1]) && isxdigit(src[2])) {
                *dest++ = hex_to_char(src[1], src[2]);
                src += 3;  // Lewati %xx
            } else {
                *dest++ = *src++;
            }
        } else if (*src == '+') {
            *dest++ = ' ';  // Konversi '+' menjadi spasi
            src++;
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';  // Null-terminate string hasil decode
}

RequestHeader parse_request_line(char *request) {
    RequestHeader req_header = {0};  // Inisialisasi struktur
    req_header.directory = strdup("/");
    req_header.uri = strdup("index.html");
    req_header.query_string = strdup("");
    req_header.path_info = strdup("");
    req_header.request_time = strdup("");
    req_header.content_type = strdup("");
    req_header.content_length = 0;
    req_header.body_data = strdup("");

    const char *line = request;
    int line_count = 0;

    while (line && *line) {
        const char *next_line = strstr(line, "\r\n");
        size_t line_length = next_line ? (size_t)(next_line - line) : strlen(line);
        if (line_length == 0) {
            line = next_line ? next_line + 2 : NULL;
            break;
        }

        char *line_copy = strndup(line, line_length);
        if (!line_copy) break;

        if (line_count == 0) {  // **Parsing Baris Pertama**
            char *words[3] = {NULL, NULL, NULL};
            int i = 0;
            char *token = strtok(line_copy, " ");
            while (token && i < 3) {
                words[i++] = token;
                token = strtok(NULL, " ");
            }

            if (i == 3) {
                strncpy(req_header.method, words[0], sizeof(req_header.method) - 1);
                free(req_header.uri);
                req_header.uri = strdup(words[1]);
                strncpy(req_header.http_version, words[2], sizeof(req_header.http_version) - 1);

                char *original_uri = strdup(words[1]);  
                if (!original_uri) return req_header;

                // Pisahkan query string jika ada
                char *query_start = strchr(original_uri, '?');
                if (query_start) {
                    *query_start = '\0';  // Pisahkan URI dan Query String
                    char *query_decoded = malloc(strlen(query_start + 1) + 1);
                    if (query_decoded) {
                        url_decode(query_start + 1, query_decoded);
                        req_header.query_string = query_decoded;
                    } 
                } 

                // **Gunakan REGEX untuk Parsing directory, URI dan PATH INFO**
                regex_t regex;
                regmatch_t matches[4];
                const char *pattern = "^(/?.*/)?([^/]+\\.[a-zA-Z0-9]+)(/.*)?$";
                regcomp(&regex, pattern, REG_EXTENDED);

                if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
                    write_log(" * Error in parse_request_line : Regex compilation failed!");
                    return req_header;
                }
                
                if (strcmp(original_uri, "/") == 0) {
                    free(req_header.uri);
                    req_header.uri = strdup("index.html");
                    free(original_uri);
                    regfree(&regex);
                    return req_header;
                }

                if (regexec(&regex, original_uri, 4, matches, 0) == 0) {
                    if (matches[1].rm_so != -1) {  // Directory
                        free(req_header.directory);
                        req_header.directory = strndup(original_uri + matches[1].rm_so,
                                                       matches[1].rm_eo - matches[1].rm_so);
                    }
                    if (matches[2].rm_so != -1) {  // URI (File)
                        free(req_header.uri);
                        req_header.uri = strndup(original_uri + matches[2].rm_so,
                                                 matches[2].rm_eo - matches[2].rm_so);
                    }
                    if (matches[3].rm_so != -1 && matches[3].rm_eo > matches[3].rm_so) {  
                        free(req_header.path_info);
                        req_header.path_info = strndup(original_uri + matches[3].rm_so, 
                                                    matches[3].rm_eo - matches[3].rm_so);
                    } 
                } else {
                    write_log(" * Error in parse_request_line : Regex not match!");
                    free(req_header.uri);
                    req_header.uri = strdup("index.html");
                }
                regfree(&regex);
            }
            
        } else { // Header Lines
            if (strncmp(line_copy, "Encrypted: ", 11) == 0) {
                req_header.encrypted = strdup(line_copy + 11);
            } else if (strncmp(line_copy, "Request-Time: ", 14) == 0) {
                req_header.request_time = strdup(line_copy + 14);
            } else if (strncmp(line_copy, "Content-Type: ", 14) == 0) {
                req_header.content_type = strdup(line_copy + 14);
            } else if (strncmp(line_copy, "Content-Length: ", 16) == 0) {
                req_header.content_length = atoi(line_copy + 16);
            }
        }

        free(line_copy);
        line = next_line ? next_line + 2 : NULL;
        line_count++;
    }

    if (line && *line) {
        if (req_header.encrypted && strcmp(req_header.encrypted, "yes") == 0) {
            req_header.body_data = strdup(line);
            sanitize_base64_input(req_header.body_data);
        } else {
            char *body_decoded = malloc(strlen(line) + 1);
            if (body_decoded) {
                url_decode(line, body_decoded);
                req_header.body_data = body_decoded;
            }
        }
    }

    if (!req_header.uri || strlen(req_header.uri) == 0) {
        free(req_header.uri);  // Aman walau NULL
        req_header.uri = strdup("index.html");
    }

    return req_header;
} //end parse_request_line

const char *get_mime_type(const char *file) {
    // Cari extension dari file
    const char *dot = strrchr(file, '.');

    // Jika tidak ditemukan extension atau MIME type yang cocok,
    // kembalikan "text/html" sebagai default
    if (!dot) return "text/html";
    else if (strcmp(dot, ".html") == 0) return "text/html";
    else if (strcmp(dot, ".css") == 0) return "text/css";
    else if (strcmp(dot, ".js") == 0) return "application/js";
    else if (strcmp(dot, ".jpg") == 0) return "image/jpeg";
    else if (strcmp(dot, ".png") == 0) return "image/png";
    else if (strcmp(dot, ".gif") == 0) return "image/gif";
    else if (strcmp(dot, ".ico") == 0) return "image/ico";
    else return "text/html";  // Default MIME type
} //end get_mime_type

char *get_time_string() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    // Mengambil waktu dalam format struct tm (GMT)
    struct tm *tm_info = localtime(&tv.tv_sec);

    // Alokasikan buffer yang cukup besar untuk waktu dan milidetik
    char *buf = (char *)malloc(64);  // Ukuran buffer yang memadai
    if (!buf) return NULL;  // Cek jika malloc gagal

    // Format waktu tanpa milidetik terlebih dahulu
    strftime(buf, 64, "%a, %d %b %Y %H:%M:%S", tm_info);
    
    // Tambahkan milidetik ke string
    int millis = tv.tv_usec / 1000;
    snprintf(buf + strlen(buf), 64 - strlen(buf), ".%03d GMT", millis);

    return buf;
} //end get_time_string

char *generate_response_header(ResponseHeader res_header) {
    char *header = malloc(BUFFER_SIZE);
    if (header == NULL) {
        return NULL;
    }

    snprintf(
        header, BUFFER_SIZE,
        "%s %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache\r\n"
        "Response-Time: %s\r\n"
        "Encrypted: %s\r\n"
        "\r\n",  // Akhir dari header
        res_header.http_version, res_header.status_code, 
        res_header.status_message, res_header.mime_type, 
        res_header.content_length, res_header.response_time, 
        res_header.encrypted);
    
    return header;
} // generate_response_header

char *create_response(
    int *response_size, 
    ResponseHeader *res_header, 
    const char *body, int body_size, int encrypted) {
        
    char *response = NULL;

    //char *encrypt_body;
    char *final_body;
    int final_body_size;
    char *responseTime = get_time_string();
    write_log(" * Start Response");
    if(encrypted == 1) {
        write_log(" ** Ecrypted : yes");
        write_log(" *** Original data size : %d bytes", body_size);
       
        // =================== Kompresi
        size_t compressed_size = 0;
        uint8_t *compressed = compress_brotli(body, body_size, &compressed_size);
        if (!compressed) {
            write_log(" * Error in crate response : Compression failed!");
            return NULL;
        }
        write_log(" *** Compression data size : %d bytes", compressed_size);
        write_log(" *** Ratio compression : %.2f%%", ((double)(body_size - compressed_size) / body_size) * 100);

        // ====================== Encrypt
        char *java_key = masehi2jawa(responseTime);
        char *hash_key = sha256_hash(java_key);
        uint8_t buffer_key[44];
        hex_to_bytes(hash_key, buffer_key, 32);
        uint8_t key[32];
        uint8_t nonce[12];
        memcpy(key, buffer_key, 32);
        memcpy(nonce, buffer_key + 20, 12);

        uint8_t *ciphertext = chacha20_crypt((const uint8_t*)compressed, compressed_size, key, nonce);
        if (!ciphertext) {
            write_log(" * Error in crate response : Encryption failed!");
            return NULL;
        }
        
        write_log(" *** Public Key : %s", responseTime);
        write_log(" *** Javanese time Key : %s", java_key);
        write_log(" *** Hash Private Key : %s", hash_key);


        // ====================== Encode Base64
        char *cipher_b64 = base64_encode(ciphertext, compressed_size);
        size_t b64_len = strlen(cipher_b64);
        write_log(" *** Encode base64 data size : %zu byte", b64_len);
        write_log(" *** Rasio Base64  : %.2f%%", ((double)(body_size - b64_len) / body_size) * 100);

        final_body_size = b64_len;

        // Alokasikan memori untuk final_body
        final_body = (char *)malloc(final_body_size);
        if (!final_body) {
            free(java_key);
            free(hash_key);
            return NULL;
        }

        // Gabungkan encrypt_body, separator, dan public_key
        strcpy(final_body, cipher_b64);

        res_header->encrypted = "yes";

        // Bebaskan memori yang tidak lagi diperlukan
        free(java_key);
        free(hash_key);
    } else {
        final_body = (char *)body;  // Use body directly if not encrypted
        final_body_size = body_size;
        res_header->encrypted = "no";
        write_log(" ** Ecrypted : no");
    }

    res_header->response_time = responseTime;
    res_header->content_length = body_size;
    // Generate response header
    char *response_header = generate_response_header(*res_header);
    if (!response_header) return NULL;

    // Allocate memory for full response
    int header_size = strlen(response_header);

    response = (char *)malloc(header_size + final_body_size);
    if (response) {
        memcpy(response, response_header, header_size);   // Copy header
        memcpy(response + header_size, final_body, final_body_size);  // Copy body
        *response_size = header_size + final_body_size;

        write_log(" ** Send to browser");
        write_log(" *** Header data size : %d bytes", header_size);
        write_log(" *** Body data size : %d bytes", final_body_size);
        write_log(" *** Total Data Size : %d bytes", (header_size + final_body_size));
    }
    free(responseTime);
    free(response_header);
    if(encrypted == 1)
        free(final_body);

    //log
    write_log(" * Status Response : %s %d %s", 
        res_header->http_version, 
        res_header->status_code, 
        res_header->status_message);

    // Hanya untuk menampilkan hasil uji coba
    // Jika diimplementasikan beneran, printf dihapus
    // printf("\nResponse Ciphertext ke browser\n%s\n", response);

    return response;
}

char* get_content_type(const char *header) {
    const char *content_type_start = strstr(header, "Content-Type:");
    if (!content_type_start) return NULL;  // Jika tidak ditemukan, return NULL

    content_type_start += 13;  // Geser ke setelah "Content-Type:"

    // Hilangkan spasi yang mungkin ada di depan
    while (*content_type_start == ' ') {
        content_type_start++;
    }

    // Ambil nilai Content-Type
    char *content_type = strdup(content_type_start);
    char *newline_pos = strchr(content_type, '\n'); // Cari akhir baris
    if (newline_pos) *newline_pos = '\0';  // Potong di newline

    return content_type;  // Return hasil (jangan lupa free() setelah digunakan)
}

char *handle_method(int *response_size, RequestHeader req_header) {
    char *response = NULL;  // Single pointer untuk response
    int encrypt = 0;

    write_log(" * Req URI : %s", req_header.uri);
    // Pengecekan apakah method, uri, atau http_version kosong
    if (strlen(req_header.method) == 0 || strlen(req_header.uri) == 0 || strlen(req_header.http_version) == 0) {
        ResponseHeader res_header = {
            .http_version = "HTTP/1.1",
            .status_code = 400,
            .status_message = "Bad Request",
            .mime_type = "text/html",
            .content_length = 0,
            .encrypted = ""
        };

        char *_400 = "<h1>400 Bad Request</h1>";
        response = create_response(response_size, &res_header, _400, strlen(_400), encrypt);
        return response;
    }

    // Buka file (resource) yang diminta oleh web browser
    char fileURL[BUFFER_SIZE];
    snprintf(fileURL, sizeof(fileURL), "%s%s", config.document_root, req_header.uri);
    FILE *file = fopen(fileURL, "rb");

    if (!file) {
        // Jika file tidak ditemukan, kirimkan status 404 Not Found
        ResponseHeader res_header = {
            .http_version = req_header.http_version,
            .status_code = 404,
            .status_message = "Not Found",
            .mime_type = "text/html",
            .content_length = 0,
            .encrypted = ""
        };

        char *_404 = "<h1>Not Found</h1>";
        response = create_response(response_size, &res_header, _404 , strlen(_404), encrypt);
        return response;
    } 

    if(file) {
        // Jika file resource ditemukan
        // Ambil data MIME type
        const char *extension = strrchr(req_header.uri, '.');
        
        if (extension && strcmp(extension, ".php") == 0) {
            //char *post_data = NULL;
            if (strcmp(req_header.body_data, "") > 0) {
                char *cipher_b64 = NULL;
                uint8_t *cipher_bin = NULL;
                char *java_key = NULL;
                char *hash_key = NULL;
                uint8_t *decrypted = NULL;
                char *decompressed = NULL;
                if (req_header.encrypted != NULL && strcmp(req_header.encrypted, "yes") == 0) {
                    write_log(" ** Encrypted body data : yes");
                    size_t cipher_size = strlen(req_header.body_data);
                    cipher_b64 = malloc(cipher_size + 1);
                    if (!cipher_b64) {
                        write_log(" ** Error : Base64 decoding Memory allocation failed!");
                        goto cleanup;
                    }

                    strcpy(cipher_b64, req_header.body_data);
                    cipher_b64[cipher_size] = '\0';

                    size_t cipher_len = 0;
                    cipher_bin = base64_decode(cipher_b64, &cipher_len);
                    if (!cipher_bin) {
                        write_log(" ** Error : Base64 decoding failed!");
                        goto cleanup;
                    }

                    java_key = masehi2jawa(req_header.request_time);
                    hash_key = sha256_hash(java_key);
                    if (!java_key || !hash_key) {
                        write_log(" ** Error : Key generation failed!");
                        goto cleanup;
                    }

                    uint8_t buffer_key[44];
                    hex_to_bytes(hash_key, buffer_key, 32);
                    uint8_t key[32], nonce[12];
                    memcpy(key, buffer_key, 32);
                    memcpy(nonce, buffer_key + 20, 12);

                    decrypted = chacha20_crypt(cipher_bin, cipher_len, key, nonce);
                    if (!decrypted) {
                        write_log(" ** Error : Decryption failed!");
                        goto cleanup;
                    }

                    size_t decompressed_size = 0;
                    decompressed = decompress_brotli(decrypted, cipher_len, &decompressed_size);
                    if (!decompressed) {
                        write_log(" ** Error : Decompression failed!");
                        goto cleanup;
                    }

                    strcpy(req_header.body_data, decompressed);

                    write_log(" ** Cipher Base64 :%s", cipher_b64);
                    write_log(" ** Cipher Data Size : %ld bytes", cipher_size);
                    write_log(" ** Decode Base64 Data Size : %ld bytes", cipher_len);
                    write_log(" ** Public key : %s", req_header.request_time);
                    write_log(" ** Javanese times key : %s", java_key);
                    write_log(" ** Hash Private key : %s", hash_key);
                    write_log(" ** Decompression Data size : %ld bytes", decompressed_size);
                    write_log(" ** Plaintext Body Data : %s", req_header.body_data);
                }
                cleanup:
                    free(cipher_b64);
                    free(cipher_bin);
                    free(java_key);
                    free(hash_key);
                    free(decrypted);
                    free(decompressed);
            }

            write_log(" * Start request to PHP");
            ResponseHeader res_header;
            int php_has_error = 0;  // Flag untuk menandakan ada error
            Response_PHP_FPM php_fpm = php_fpm_request(
                req_header.directory,
                req_header.uri, 
                req_header.method, 
                req_header.query_string,
                req_header.path_info, 
                req_header.body_data, 
                req_header.content_type);

            char *_php_header = php_fpm.header ? strdup(php_fpm.header) : strdup(""); 
            char *_php_body = php_fpm.body ? strdup(php_fpm.body) : strdup(""); 

            if (strstr(_php_header, "Status: 500 Internal Server Error")) {
                php_has_error = 1;
                res_header.http_version = req_header.http_version,
                res_header.status_code = 500,
                res_header.status_message = "Internal Server Error",
                res_header.mime_type = "text/html",
                res_header.content_length = strlen(_php_body);
                write_log(" * Status Response from PHP : %s %d %s", 
                    req_header.http_version, 
                    500, 
                    "Internal Server Error"
                );
            } else {
                //Content-Type: application/json
                res_header.http_version = req_header.http_version,
                res_header.status_code = 200,
                res_header.status_message = "OK",
                res_header.mime_type = get_content_type(_php_header),
                res_header.content_length = strlen(_php_body);
                write_log(" * Status Response from PHP : %s %d %s", 
                    req_header.http_version, 
                    200, 
                    "OK"
                );
            }

            if(php_has_error == 0) {
                response = create_response(response_size, &res_header, _php_body , strlen(_php_body), 1);
            } else {
                response = create_response(response_size, &res_header, _php_body , strlen(_php_body), 0);
            }
            free(_php_body);

            // Bebaskan `php_fpm.body` untuk mencegah memory leak
            free(php_fpm.header);
            free(php_fpm.body);
            return response;
        } else {
            const char *mime = get_mime_type(req_header.uri);

            // Generate header 200 OK
            ResponseHeader res_header = {
                .http_version = req_header.http_version,
                .status_code = 200,
                .status_message = "OK",
                .mime_type = mime,
                .content_length = 0,
                .encrypted = ""
            };

            // Baca file resource dari server
            fseek(file, 0, SEEK_END);
            long fsize = ftell(file);
            fseek(file, 0, SEEK_SET);

            char *response_body = (char *)malloc(fsize + 1);
            fread(response_body, 1, fsize, file);
            fclose(file);
    
            /*if ( 
                (strcmp(mime, "text/html") == 0)  || 
                (strcmp(mime, "text/css") == 0) || 
                (strcmp(mime, "application/js") == 0)
            )
                encrypt = 1;
            */

            if (strcmp(mime, "text/html") == 0)
                encrypt = 1;

            response = create_response(response_size, &res_header, response_body, fsize, encrypt);
            free(response_body);
            return response;  
        }
    }
    return NULL;
} // handle_method
