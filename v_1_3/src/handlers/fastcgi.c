#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h> 

#include "http_utils.h"
#include "config.h"
#include "log.h"
#include "fastcgi.h"

extern Config config;

#define BUFFER_SIZE 4096

#define MAX_RESPONSE_SIZE 52428800

/***********************************************************************
 * trim_header_value()
 * ANALOGI :
 * Fungsi ini seperti PETUGAS YANG MERAPIKAN TULISAN di formulir.
 * Kalau ada spasi, tab, atau enter di depan teks,
 * dia geser pena sampai ketemu huruf pertama yang benar.
 *
 * Contoh:
 * "   text/html" → "text/html"
 ***********************************************************************/
const char* trim_header_value(const char* s) {
    if (!s) return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

/***********************************************************************
 * add_pair()
 * ANALOGI :
 * Ini seperti petugas yang MEMASUKKAN SATU KOLOM FORMULIR
 * ke dalam amplop FastCGI.
 *
 * Langkahnya:
 * 1. Nama kolom ditulis dulu (misal: SCRIPT_NAME)
 * 2. Isinya dibersihkan dari spasi aneh
 * 3. Dimasukkan berurutan: [panjang nama][panjang nilai][nama][nilai]
 *
 * Kalau amplop sudah kepenuhan → dia menolak (return 0).
 ***********************************************************************/

int add_pair(unsigned char* dest, const char *name, const char *value, int current_offset, int max_len) {
    int name_len = (int)strlen(name);
    const char* val_ptr = value ? value : "";
    int value_len = (int)strlen(val_ptr);

    // Hitung butuh berapa byte buat nyimpen 'length'
    int name_len_bytes = (name_len > 127) ? 4 : 1;
    int value_len_bytes = (value_len > 127) ? 4 : 1;

    // Cek apakah buffer params_buf masih muat
    if (current_offset + name_len_bytes + value_len_bytes + name_len + value_len > max_len) {
        return 0; // Gak muat, Cuk!
    }

    int offset = current_offset;

    // --- Tulis Name Length ---
    if (name_len > 127) {
        dest[offset++] = (unsigned char)((name_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((name_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((name_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(name_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)name_len;
    }

    // --- Tulis Value Length ---
    if (value_len > 127) {
        dest[offset++] = (unsigned char)((value_len >> 24) | 0x80);
        dest[offset++] = (unsigned char)((value_len >> 16) & 0xFF);
        dest[offset++] = (unsigned char)((value_len >> 8) & 0xFF);
        dest[offset++] = (unsigned char)(value_len & 0xFF);
    } else {
        dest[offset++] = (unsigned char)value_len;
    }

    // --- Tulis Datanya ---
    memcpy(dest + offset, name, name_len);
    offset += name_len;
    memcpy(dest + offset, val_ptr, value_len);
    offset += value_len;

    return (offset - current_offset); // Balikin jumlah byte yang kepake
}

/***********************************************************************
 * send_begin_request
 * ANALOGI :
 * Ini seperti MEMUKUL BEL PERTAMA ke backend FastCGI:
 * "Halo PHP-FPM, saya mau mulai satu pekerjaan baru!"
 *
 * Paket BEGIN_REQUEST adalah salam pembuka
 * sebelum kita kirim data formulir sesungguhnya.
 ***********************************************************************/
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

/***********************************************************************
 * send_params()
 * ANALOGI :
 * Setelah bilang "mau mulai",
 * petugas mengirim TUMPUKAN FORMULIR IDENTITAS :
 *
 * - nama file skrip
 * - metode GET/POST
 * - query string
 * - dll
 *
 * Kalau formulir tidak kelipatan 8 byte,
 * ditambah kertas kosong (padding) biar rapi seperti standar pos.
 *
 * Terakhir dikirim paket kosong → tanda "formulir sudah habis".
 ***********************************************************************/
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

/***********************************************************************
 * send_stdin()
 * ANALOGI :
 * Ini adalah BAGIAN KURIR PENGIRIM LAMPIRAN BESAR.
 *
 * Kalau user upload file 10MB:
 * - tidak dikirim sekali jalan,
 * - tapi dicacah jadi paket kecil (chunk).
 *
 * Setiap chunk:
 * 1. Diberi amplop FastCGI
 * 2. Dikirim
 * 3. Diberi padding kalau perlu
 *
 * Setelah semua terkirim,
 * dikirim amplop kosong → tanda EOF -End Of File (selesai).
 ***********************************************************************/
void send_stdin(int sockfd, int request_id, const void *post_data, int post_data_len) {
    // printf("\n[DEBUG STDIN] --- START CHUNKING SEND_STDIN ---\n");
    // printf("[DEBUG STDIN] Total Data to Send: %d bytes\n", post_data_len);

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
        // printf("[DEBUG STDIN] Sent chunk: %d bytes. Progress: %d/%d\n", chunk_size, sent_so_far, post_data_len);
    }

    // WAJIB: Kirim paket STDIN kosong (EOF) setelah semua chunk habis
    FCGI_Header empty_stdin = {0};
    empty_stdin.version = FCGI_VERSION_1;
    empty_stdin.type = 5;
    empty_stdin.requestIdB1 = (request_id >> 8) & 0xFF;
    empty_stdin.requestIdB0 = request_id & 0xFF;
    send(sockfd, &empty_stdin, 8, 0);
    
    // printf("[DEBUG STDIN] --- ALL CHUNKS SENT ---\n\n");
}

/***********************************************************************
 * fcgi_response()
 * ANALOGI :
 * Ini adalah PETUGAS PENERIMA BALASAN dari PHP-FPM.
 *
 * Dia membaca paket demi paket:
 * - kalau tipe STDOUT → itu isi jawaban PHP/Rust
 * - kalau tipe END_REQUEST → tanda selesai
 *
 * Setelah terkumpul:
 * dipisah jadi 2 bagian:
 *   1. header HTTP dari PHP/Rust
 *   2. body output
 *
 * Seperti membuka amplop balasan dari backend.
 ***********************************************************************/
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

/***********************************************************************
 * cgi_request_stream
 * ANALOGI BESAR – FUNGSI PALING CANGGIH :
 *
 * Ini seperti JEMBATAN LANGSUNG antara:
 * → Browser ↔ Halmos ↔ PHP-FPM
 *
 * Beda dengan fastcgi_request biasa:
 * fungsi ini bisa mengalirkan body SECARA STREAMING,
 * bukan menunggu semua data terkumpul dulu.
 *
 * Langkahnya:
 * A. Sambung ke backend (seperti membuka pintu gudang)
 * B. Kirim identitas request (params)
 * C. Kirim body bertahap:
 *    - sisa yang sudah dibaca parser
 *    - lanjut langsung dari socket client
 * D. Kirim tanda selesai (STDIN kosong)
 * E. Terima jawaban dari FPM
 *
 * Ibarat:
 * → seperti pipa air langsung,
 *    bukan ember yang harus penuh dulu.
 ***********************************************************************/
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

    // 1. Koneksi ke Backend (PHP-PHP-FPM /Rust-spawn-fcgi)
    int fpm_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in fpm_addr;
    memset(&fpm_addr, 0, sizeof(fpm_addr));
    fpm_addr.sin_family = AF_INET;
    fpm_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &fpm_addr.sin_addr);

    if (connect(fpm_sock, (struct sockaddr *)&fpm_addr, sizeof(fpm_addr)) < 0) {
        //printf("[ERROR] Backend Down at %s:%d\n", target_ip, target_port);
        return res; 
    }

    // 2. Kirim BEGIN_REQUEST & PARAMS
    send_begin_request(fpm_sock, request_id);

    // --- PERBAIKAN DI SINI ---
    // Gunakan buffer yang lebih besar (16KB) untuk menampung params (header)
    unsigned char params_buf[16384]; 
    int p_len = 0;
    int written = 0;
    
    // Helper macro lokal biar gak ngetik ulang check return value
    #define PUSH_PARAM(name, val) \
        written = add_pair(params_buf, name, val, p_len, sizeof(params_buf)); \
        if (written > 0) p_len += written; \
        else write_log("[FCGI] Warning: Buffer full, skipped %s", name);
    
    // 3. Sesuaikan path file
    char script_filename[1024];
    snprintf(script_filename, sizeof(script_filename), "%s/%s", config.document_root, script_name);

    // 4. Format Content-Length string
    char cl_str[20];
    snprintf(cl_str, sizeof(cl_str), "%zu", content_length);

    // 5. Sanitize Content-Type
    const char *clean_ct = content_type ? content_type : "";
    while(*clean_ct == ' ') clean_ct++; 

    // 6. Siapkan variabel buat nampung IP browser yang mengakses
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN] = "0.0.0.0"; // Default kalau gagal

    // 7. Tanya ke Kernel: "Woi, socket ini punya siapa?"
    if (getpeername(sock_client, (struct sockaddr *)&addr, &addr_size) == 0) {
        // Convert format binary ke string (misal: 192.168.1.1)
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    // 6. Isi Semua Parameter (Pakai Macro yang tadi kita buat)
    PUSH_PARAM("SCRIPT_FILENAME", script_filename);
    PUSH_PARAM("REQUEST_METHOD", method);
    PUSH_PARAM("CONTENT_LENGTH", cl_str);
    PUSH_PARAM("CONTENT_TYPE", content_type ? content_type : "");
    PUSH_PARAM("QUERY_STRING", query_string ? query_string : "");
    // --- KHUSUS POST HARUS JELAS ---
    const char *sanitized_ct = trim_header_value(content_type);
    if (strcmp(method, "POST") == 0) {
        PUSH_PARAM("CONTENT_LENGTH", cl_str);
        // Kalau content_type dari browser kosong, kasih default form
        if (sanitized_ct && strlen(sanitized_ct) > 0) {
        PUSH_PARAM("CONTENT_TYPE", sanitized_ct);
        } else {
            PUSH_PARAM("CONTENT_TYPE", "application/x-www-form-urlencoded");
        }
    } else {
        // Kalau GET, biasanya length 0
        PUSH_PARAM("CONTENT_LENGTH", "0");
        PUSH_PARAM("CONTENT_TYPE", "");
    }
    PUSH_PARAM("REQUEST_URI", script_name);
    PUSH_PARAM("SERVER_PROTOCOL", "HTTP/1.1");
    PUSH_PARAM("GATEWAY_INTERFACE", "CGI/1.1");
    PUSH_PARAM("REMOTE_ADDR", client_ip);
    PUSH_PARAM("REDIRECT_STATUS", "200");

    // Masukkan Cookie jika ada
    if (cookie_data) {
        PUSH_PARAM("HTTP_COOKIE", cookie_data);
    }

    send_params(fpm_sock, request_id, params_buf, p_len);

    // 7. PROSES STREAMING BODY
    size_t total_streamed = 0;

    // 7.1. Kirim sisa data yang sudah "nyangkut" di parser Halmos
    if (post_data_len > 0 && post_data != NULL) {
        send_stdin(fpm_sock, request_id, post_data, (int)post_data_len);
        total_streamed += post_data_len;
    }

    // 7.2. Baca sisanya langsung dari socket client dan "tembak" ke FPM
    if (sock_client != -1 && total_streamed < content_length) {
        char stream_buffer[16384]; 
        while (total_streamed < content_length) {
            ssize_t n = recv(sock_client, stream_buffer, sizeof(stream_buffer), 0);
            if (n > 0) {
                send_stdin(fpm_sock, request_id, stream_buffer, (int)n);
                total_streamed += n;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Tunggu bentar data dateng, jangan langsung break
                usleep(100); 
                continue; 
            } else {
                break; 
            }
        }
    }

    // 8. WAJIB: Kirim STDIN Kosong sebagai tanda SELESAI
    send_stdin(fpm_sock, request_id, NULL, 0);

    // 9. Terima Balasan
    res = fcgi_response(fpm_sock);
    
    close(fpm_sock);
    return res;
}
