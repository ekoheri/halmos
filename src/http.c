#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "../include/http.h"
#include "../include/config.h"
#include "../include/log.h"
#include "../include/sha256.h"
#include "../include/chacha20.h"
#include "../include/pasaran.h"

#define BUFFER_SIZE 1024

extern Config config;

RequestHeader parse_request_line(char *request) {
    RequestHeader req_header = {
        .method = "",
        .uri = "",
        .http_version = "",
        .query_string = "",
        .post_data = "",
        .encrypted = "",
        .request_time = ""
    };

    int request_buffer_size = 8 * BUFFER_SIZE;
    char request_message[request_buffer_size];
    char request_line[BUFFER_SIZE];
    char *words[3] = {NULL, NULL, NULL};

    // Inisialisasi semua field struct
    memset(&req_header, 0, sizeof(req_header));

    if (request == NULL || strlen(request) == 0) {
        return req_header;  // Kembalikan struct kosong jika input tidak valid
    }

    // Baca baris pertama dari rangkaian data request
    strncpy(request_message, request, request_buffer_size);
    request_message[request_buffer_size - 1] = '\0'; 
    char *first_line = strtok(request_message, "\r\n");
    if (first_line == NULL) {
        return req_header;
    }
    strncpy(request_line, first_line, BUFFER_SIZE);
    request_line[BUFFER_SIZE - 1] = '\0';

    //log
    write_log(" * Request : %s", request_line);

    // Pilah request line berdasarkan spasi
    int i = 0;
    char *token = strtok(request_line, " ");
    while (token != NULL && i < 3) {
        words[i++] = token;
        token = strtok(NULL, " ");
    }

    // Pastikan ada 3 komponen dalam request line
    if (i < 3) {
        return req_header;
    }

    // kata 1 : Method, kata 2 : uri, kata 3 : versi HTTP
    strcpy(req_header.method, words[0]);
    strcpy(req_header.uri, words[1]);
    strcpy(req_header.http_version, words[2]);

    // Hapus tanda / pada URI
    if (req_header.uri[0] == '/') {
        memmove(req_header.uri, req_header.uri + 1, strlen(req_header.uri));
    }

    // Cek apakah ada query string
    char *query_start = strchr(req_header.uri, '?');
    if (query_start != NULL) {
        // Pisahkan query string dari URI
        *query_start = '\0'; 
        // Salin query string
        strcpy(req_header.query_string, query_start + 1); 
    } else {
        // Tidak ada query string
        req_header.query_string[0] = '\0'; 
    }

    const char *line = request;
    // Memproses setiap baris
    while (line && *line) {
        const char *next_line = strstr(line, "\r\n");
        size_t line_length = next_line ? (size_t)(next_line - line) : strlen(line);

        if (line_length > 0) {
            char *line_copy = strndup(line, line_length);

            if (strncmp(line_copy, "Encrypted: ", 11) == 0) {
                req_header.encrypted = strdup(line_copy + 11);
            } else if (strncmp(line_copy, "Request-Time: ", 14) == 0) {
                req_header.request_time = strdup(line_copy + 14);
            } else if (strncmp(line_copy, "Content-Length: ", 16) == 0) {
                req_header.content_length = atoi(line_copy + 16);
            } 

            free(line_copy);
        }

        line = next_line ? next_line + 2 : NULL; // Pindah ke baris berikutnya
    }
    
    // Cek apakah ada body data
    char *body_start = strstr(request, "\r\n\r\n");
    if (body_start != NULL) {
        // Pindahkan pointer ke awal body data
        body_start += 4; // Melewati CRLF CRLF
        // Salin data POST dari body
        strcpy(req_header.post_data, body_start);
    } else {
        req_header.post_data[0] = '\0'; // Tidak ada body data
    }

    // Jika URI kosong, maka isi URI dengan resource default
    // yaitu index.html
    if (strlen(req_header.uri) == 0) {
        strcpy(req_header.uri, "index.html");
    }

    return req_header;  // Kembalikan struct
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

    char *encrypt_body;
    char *final_body;
    int final_body_size;
    char *responseTime = get_time_string();
    if(encrypted == 1) {
        char *key = masehi2jawa(responseTime);
        char *hash_key = sha256_hash(key);
        // Hanya untuk menampilkan hasil uji coba
        // Jika diimplementasikan beneran, printf dihapus
        printf("\nEncription Proccess\nTime Value : %s\n", responseTime);
        printf("Javanese time Key : %s\n", key);
        printf("Hash Key : %s\n", hash_key);

        encrypt_body = encrypt(body, hash_key, body_size);
        final_body_size = strlen(encrypt_body) + 1;

        // Alokasikan memori untuk final_body
        final_body = (char *)malloc(final_body_size);
        if (!final_body) {
            free(key);
            free(hash_key);
            return NULL;
        }

        // Gabungkan encrypt_body, separator, dan public_key
        strcpy(final_body, encrypt_body);

        res_header->encrypted = "yes";

        // Bebaskan memori yang tidak lagi diperlukan
        free(key);
        free(hash_key);
    } else {
        final_body = (char *)body;  // Use body directly if not encrypted
        final_body_size = body_size;
        res_header->encrypted = "no";
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
    }
    free(responseTime);
    free(response_header);
    if(encrypted == 1)
        free(final_body);

    //log
    write_log(" * Response : %s %d %s", 
        res_header->http_version, 
        res_header->status_code, 
        res_header->status_message);

    // Hanya untuk menampilkan hasil uji coba
    // Jika diimplementasikan beneran, printf dihapus
    printf("\nResponse Ciphertext ke browser\n%s\n", response);
    
    return response;
}

char *handle_method(int *response_size, RequestHeader req_header) {
    char *response = NULL;  // Single pointer untuk response
    int encrypt = 0;

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
            // Jalankan CGI
            char *post_data = NULL;
            if (strcmp(req_header.post_data, "") > 0) {
                if (req_header.encrypted != NULL && strcmp(req_header.encrypted, "yes") == 0) {
                    char *key = masehi2jawa(req_header.request_time);
                    char *hash_key = sha256_hash(key);

                    char *decrypt_post_data = decrypt(req_header.post_data, hash_key, req_header.content_length);
                    if (decrypt_post_data != NULL) {
                        post_data = malloc(strlen(decrypt_post_data) + 1); // Alokasikan memori untuk string
                        if (post_data != NULL) {
                            strcpy(post_data, decrypt_post_data);
                        }
                        free(decrypt_post_data);
                    } 

                    free(key);
                    free(hash_key);
                }
            }

            ResponseHeader res_header = {
                .http_version = req_header.http_version,
                .status_code = 200,
                .status_message = "OK",
                .mime_type = "text/html",
                .content_length = 0,
                .encrypted = "no"
            };

            encrypt = 1;
            response = create_response(response_size, &res_header, post_data , strlen(post_data), encrypt);
            return response;
            
            /*char command[2048];

            if (strcmp(req_header.query_string, "") > 0) {
                snprintf(command, sizeof(command), 
                "GET /%s?%s %s\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "User-Agent: EkoBrowser/1.0\r\n",
                req_header.uri, req_header.query_string, 
                req_header.http_version, config.server_name);
            } else if (strcmp(req_header.post_data, "") > 0) {
                snprintf(command, sizeof(command), 
                "POST /%s %s\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "User-Agent: EkoBrowser/1.0\r\n"
                "\r\n%s", req_header.uri, 
                req_header.http_version, config.server_name, 
                req_header.post_data);
            } else {
                snprintf(command, sizeof(command), 
                "GET /%s %s\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "User-Agent: EkoBrowser/1.0\r\n",
                req_header.uri, req_header.http_version, config.server_name);
            }

            int sock_client = -1, response_cgi = -1;
            struct sockaddr_in serv_addr;
            struct hostent *server;
            char temp_cgi_buffer[BUFFER_SIZE] = {0};
            char *response_cgi_buffer;
            char *response_cgi_body;
            int total_bytes_received = 0;
            int cgi_status_error = 0;
            size_t output_len;
            long response_cgi_buffer_size = 8 * BUFFER_SIZE;

            response_cgi_buffer = (char *)malloc(response_cgi_buffer_size);
            if (response_cgi_buffer == NULL) {
                fprintf(stderr, "Malloc response CGI buffer gagal\n");
                exit(EXIT_FAILURE);
            }
            // Mengosongkan buffer
            memset(response_cgi_buffer, 0, response_cgi_buffer_size);

            // 1. Inisialisasi socket
            if ((sock_client = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cgi_status_error = 1;
                write_log("Error: Inisialisasi socket client gagal");
            } else {
                // Mendapatkan informasi server berdasarkan nama "localhost"
                server = gethostbyname(config.server_cgi);
                if (server == NULL) {
                    cgi_status_error = 1;
                    write_log("Error: Host CGI Server tidak ditemukan");
                } else {
                    // Mengisi informasi server (IP Address & port)
                    memset(&serv_addr, 0, sizeof(serv_addr));
                    serv_addr.sin_family = AF_INET;
                    serv_addr.sin_port = htons(config.port_cgi);
                    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

                    // 2. Connect ke server
                    if (connect(sock_client, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                        cgi_status_error = 1;
                        write_log("Error: Koneksi ke CGI Server gagal");
                    } else {
                        // 3. Send request ke server
                        if (send(sock_client, command, strlen(command), 0) < 0) {
                            cgi_status_error = 1;
                            write_log("Error: Gagal mengirim permintaan ke Server CGI");
                        } else {
                            // 4. Read Response dari CGI server
                            memset(response_cgi_buffer, 0, response_cgi_buffer_size);
                            memset(temp_cgi_buffer, 0, BUFFER_SIZE);
                            while ((response_cgi = read(sock_client, temp_cgi_buffer, BUFFER_SIZE - 1)) > 0) {
                                temp_cgi_buffer[response_cgi] = '\0';

                                // Menyimpan respons ke buffer lengkap
                                if ((total_bytes_received + response_cgi) < (response_cgi_buffer_size - 1)) {
                                    strcat(response_cgi_buffer, temp_cgi_buffer);
                                    total_bytes_received += response_cgi;
                                } else {
                                    response_cgi_buffer_size *= 2;
                                    response_cgi_buffer = realloc(response_cgi_buffer, response_cgi_buffer_size);
                                }
                                // Reset buffer untuk pembacaan berikutnya
                                memset(temp_cgi_buffer, 0, BUFFER_SIZE);
                            }

                            if (response_cgi < 0) {
                                cgi_status_error = 1;
                                write_log("Error: Gagal menerima respon dari CGI Server");
                            }
                        }
                    }
                }
            }

            if (sock_client >= 0) close(sock_client);

            ResponseHeader res_header = {
                .http_version = req_header.http_version,
                .status_code = 200,
                .status_message = "OK",
                .mime_type = "text/html",
                .content_length = 0,
                .encrypted = ""
            };

            if (cgi_status_error == 0) {
                // Ambil response body dari CGI
                response_cgi_body = strstr(response_cgi_buffer, "\r\n\r\n");
                if (response_cgi_body) {
                    response_cgi_body += 4;
                    output_len = strlen(response_cgi_body);
                    encrypt = 1;
                } else {
                    write_log("Error: Tidak ditemukan delimiter header dalam response CGI");
                    res_header.status_code = 500;
                    res_header.status_message = "Internal Server Error";
                    response_cgi_body = "<h1>Internal Server Error</h1>";
                    output_len = strlen(response_cgi_body);
                    encrypt = 0;
                }
            } else {
                res_header.status_code = 500;
                res_header.status_message = "Internal Server Error";
                response_cgi_body = "<h1>Internal Server Error</h1>";
                output_len = strlen(response_cgi_body);
                encrypt = 0;
            }

            response = create_response(response_size, &res_header, response_cgi_body, output_len, encrypt);
            free(response_cgi_buffer);
            return response;
            */
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

            if (strcmp(mime, "text/html") == 0)
                encrypt = 1;
            response = create_response(response_size, &res_header, response_body, fsize, encrypt);
            free(response_body);
            return response;  
        }
    }
    return NULL;
} // handle_method
