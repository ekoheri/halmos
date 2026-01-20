#define _GNU_SOURCE // Penting untuk memmem()

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
#include <arpa/inet.h>

#include <dirent.h>
#include <sys/stat.h>

//Tambahan untuk library zerro-copy
#include <sys/sendfile.h>
#include <netinet/tcp.h> // Untuk TCP_NODELAY
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>  // Wajib untuk fungsi stat() dan makro S_ISREG
#include <sys/types.h> // Mendukung definisi tipe data sistem

//// Fungsi untuk membersihkan path dan mencegah traversal
#include <limits.h>

#include <sched.h>   // Header untuk sched_yield()

#include "fs_handler.h"
#include "config.h"
#include "log.h"
#include "queue.h"

#include "fastcgi.h"
#include "multipart.h"
#include "uwsgi_handler.h"

#include "http_utils.h"
#include "http_common.h"

#include "http1_parser.h"
#include "http1_handler.h"
#include "http1_response.h"

#define BUFFER_SIZE 1024

extern Config config;

extern TaskQueue global_queue;

/********************************************************************
 * parse_request_line()
 * ANALOGI :
 * Petugas loket yang membaca BARIS PERTAMA surat pesanan.
 *
 * Tamu datang membawa tulisan:
 *    "GET /produk?id=10 HTTP/1.1"
 *
 * Tugas petugas ini:
 * - Memisahkan jenis layanan  → GET / POST (seperti jenis menu)
 * - Memisahkan alamat tujuan  → /produk
 * - Membaca catatan kecil     → ?id=10 (query string)
 * - Mengetahui gaya bahasa    → HTTP/1.1
 *
 * Kalau formatnya rusak → petugas langsung bilang:
 * “Maaf formulir tidak terbaca.”
 ********************************************************************/
static void parse_request_line(char *line, RequestHeader *req) {
    char *m = strtok(line, " ");
    char *u = strtok(NULL, " ");
    char *v = strtok(NULL, " ");

    if (m && u) {
        strncpy(req->method, m, sizeof(req->method) - 1);
        if (v) strncpy(req->http_version, v, sizeof(req->http_version) - 1);

        // 1. Pisahkan Query String jika ada
        char *q = strchr(u, '?');
        if (q) {
            req->query_string = strdup(q + 1);
            url_decode(req->query_string); // Gunakan fungsi dari utils.c
            *q = '\0';
        } else {
            req->query_string = strdup("");
        }

        // 2. Simpan URI dan Decode
        req->uri = strdup((u[0] == '/' && u[1] == '\0') ? "index.html" : u);
        url_decode(req->uri); 
        
        req->is_valid = true;
    }
}

/********************************************************************
 * parse_http_request()
 * ANALOGI :
 * Bagian Tata Usaha yang MEMBUKA AMPLOP surat secara lengkap.
 *
 * Langkah kerjanya seperti:
 * 1. Mencari lipatan surat (\r\n\r\n atau Enter 2 kali) → batas kop surat & isi
 * 2. Memanggil petugas pembaca judul (parse_request_line)
 * 3. Membaca keterangan tambahan:
 *      - Content-Length  → tebal isi surat
 *      - Content-Type    → jenis lampiran
 * 4. Menyalin isi surat ke map kerja (body)
 * 5. Kalau isinya paket multipart → kirim ke petugas bongkar paket
 *
 * Hasilnya:
 * → formulir digital yang rapi siap diproses pelayan.
 ********************************************************************/

bool parse_http_request(const char *raw_data, size_t total_received, RequestHeader *req) {
    // 1. Cari batas Header (\r\n\r\n)
    char *header_end = strstr(raw_data, "\r\n\r\n");
    if (!header_end) return false;

    size_t header_len = header_end - raw_data;
    char *header_tmp = strndup(raw_data, header_len);

    // 2. Parse Baris Pertama
    char *saveptr;
    char *line = strtok_r(header_tmp, "\r\n", &saveptr);
    if (line) {
        parse_request_line(line, req);
    }

    // 3. Loop Parsing Header Lainnya (Content-Length, Type, Connection)
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            req->content_length = atol(line + 15);
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            req->content_type = strdup(line + 13);
            trim_whitespace(req->content_type); // Gunakan fungsi dari utils.c
        } else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (strcasestr(line, "keep-alive")) req->is_keep_alive = true;
            else if (strcasestr(line, "close")) req->is_keep_alive = false;
        } else if (strncasecmp(line, "Cookie:", 7) == 0) {
            const char *val = line + 7;
            while (*val == ' ') val++; // Lewati spasi setelah titik dua
            
            // Simpan isinya (misal: "user=eko; session=123")
            req->cookie_data = strdup(val); 
        } else if (strncasecmp(line, "Host:", 5) == 0) {
            char *host_val = line + 5;
            while (*host_val == ' ') host_val++; // Trim spasi depan
            req->host = strdup(host_val);  // Simpan ke struct
            write_log("[DEBUG] Parser dapet Host: '%s'", req->host); // <--- CEK INI DI TERMINAL
        }
    }//end while
    free(header_tmp);

    // 4. Salin Body
    if (req->content_length > 0) {
        char *body_start = (char *)header_end + 4;
        size_t bytes_in_buffer = total_received - (body_start - raw_data);
        
        req->body_data = malloc(req->content_length + 1);
        if (req->body_data) {
            size_t to_copy = (bytes_in_buffer > (size_t)req->content_length) 
                             ? (size_t)req->content_length : bytes_in_buffer;
            
            memcpy(req->body_data, body_start, to_copy);
            req->body_length = to_copy;
            
            // Safety null terminator untuk data teks
            ((char*)req->body_data)[to_copy] = '\0';
        }
    }

    // 5. Jika Multipart, panggil modul multipart
    if (req->content_type && strstr(req->content_type, "multipart/form-data")) {
        parse_multipart_body(req);
    }

    return req->is_valid;
}

/********************************************************************
 * free_request_header()
 * ANALOGI :
 * Petugas kebersihan meja arsip.
 *
 * Setelah pesanan selesai:
 * - fotokopi dibuang,
 * - map dikosongkan,
 * - meja disiapkan untuk tamu berikutnya.
 *
 * Tanpa petugas ini:
 * → kantor akan penuh sampah memori.
 ********************************************************************/
void free_request_header(RequestHeader *req) {
    if (req->uri) free(req->uri);
    if (req->host) free(req->host);
    if (req->query_string) free(req->query_string);
    if (req->content_type) free(req->content_type);
    if (req->body_data) free(req->body_data);
    if (req->cookie_data) {
        free(req->cookie_data);
        req->cookie_data = NULL;
    }
    
    // Bersihkan bagian multipart jika ada
    if (req->parts) {
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].name) free(req->parts[i].name);
            if (req->parts[i].filename) free(req->parts[i].filename);
            if (req->parts[i].data) free(req->parts[i].data);
            if (req->parts[i].content_type) free(req->parts[i].content_type);
        }
        free(req->parts);
    }
}

/************************************
 * Fungsi untuk menampilkan isi direktori
*************************************/
void send_directory_listing(int sock_client, const char *path, const char *uri) {
    DIR *d = opendir(path);
    if (!d) {
        send_mem_response(sock_client, 403, "Forbidden", "<h1>403 Forbidden</h1>", false);
        return;
    }

    // Header HTML dengan sedikit CSS biar gak kaku banget
    char *body = (char *)malloc(32768); // Alokasi agak besar buat folder rame
    snprintf(body, 32768, 
        "<html><head><title>Index of %s</title>"
        "<style>body{font-family:sans-serif;} table{width:100%%; border-collapse:collapse;} "
        "th,td{text-align:left; padding:8px;} tr:nth-child(even){background:#f2f2f2;}</style>"
        "</head><body><h1>Index of %s</h1><hr><table>"
        "<tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>", uri, uri);

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0) continue;

        struct stat st;
        char full_item_path[1024];
        snprintf(full_item_path, sizeof(full_item_path), "%s/%s", path, dir->d_name);
        stat(full_item_path, &st);

        // Format Waktu
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%d-%b-%Y %H:%M", localtime(&st.st_mtime));

        // Format Ukuran
        char size_buf[32];
        if (S_ISDIR(st.st_mode)) strcpy(size_buf, "-");
        else snprintf(size_buf, sizeof(size_buf), "%lld KB", (long long)st.st_size / 1024);

        char entry[2048];
        snprintf(entry, sizeof(entry), 
            "<tr><td><a href=\"%s%s%s\">%s%s</a></td><td>%s</td><td>%s</td></tr>",
            uri, (uri[strlen(uri)-1] == '/' ? "" : "/"), dir->d_name,
            dir->d_name, (S_ISDIR(st.st_mode) ? "/" : ""), 
            time_buf, size_buf);
        
        strcat(body, entry);
    }
    closedir(d);
    strcat(body, "</table><hr><i>Halmos Engine v1.0</i></body></html>");
    
    send_mem_response(sock_client, 200, "OK", body, false);
    free(body);
}

/********************************************************************
 * handle_method()
 * ANALOGI :
 * Manajer front office / pengarah lalu lintas tamu.
 *
 * Dia hanya memutuskan:
 * - Tamu mau ngobrol lama?      → jalur WebSocket
 * - Tamu cuma melihat?          → kirim ke pelayan GET
 * - Tamu kirim berkas?          → kirim ke loket POST
 * - Metode aneh?                → satpam tolak (405)
 *
 * Manajer ini tidak mengerjakan detail,
 * hanya menunjuk petugas yang tepat.
 ********************************************************************/
void handle_method(int sock_client, RequestHeader req_header) {
    // 1. Tentukan Root-nya dulu!
    const char *active_root = get_active_root(req_header.host);

    // 2. Perbaikan URI (tetap seperti kodemu)
    if (req_header.uri[0] != '/') {
        char temp[1024];
        snprintf(temp, sizeof(temp), "/%s", req_header.uri);
        req_header.uri = strdup(temp);
    }
    
    char full_path[1024];
    // PAKAI active_root, JANGAN config.document_root
    if (active_root[strlen(active_root)-1] == '/' && req_header.uri[0] == '/') {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req_header.uri + 1);
    } else {
        snprintf(full_path, sizeof(full_path), "%s%s", active_root, req_header.uri);
    }

    // DEBUG sekarang jadi akurat
    write_log("[DEBUG] URI: %s | Active Root: %s | Full Path: %s", req_header.uri, active_root, full_path);

    struct stat st;
    if (stat(full_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char index_path[1024+32];
            // Standardisasi path index
            if (full_path[strlen(full_path)-1] == '/') {
                snprintf(index_path, sizeof(index_path), "%sindex.html", full_path);
            } else {
                snprintf(index_path, sizeof(index_path), "%s/index.html", full_path);
            }
            
            if (access(index_path, F_OK) == 0) {
                // Tambahkan index.html ke URI asli buat dilempar ke static/dynamic handler
                if (req_header.uri[strlen(req_header.uri)-1] == '/') {
                    strcat(req_header.uri, "index.html");
                } else {
                    strcat(req_header.uri, "/index.html");
                }
            } else {
                send_directory_listing(sock_client, full_path, req_header.uri);
                // Penting: Free sebelum return!
                if (req_header.uri) free(req_header.uri);
                if (req_header.query_string) free(req_header.query_string);
                if (req_header.cookie_data) free(req_header.cookie_data);
                return;
            }
        }
    }

    // 2. Jalankan Handler
    if (has_extension(req_header.uri, ".php") || 
        has_extension(req_header.uri, config.rust_ext) || 
        has_extension(req_header.uri, config.python_ext)) 
    {
        handle_dynamic_request(sock_client, &req_header);
    } else {
        if (strcmp(req_header.method, "GET") == 0) {
            handle_static_request(sock_client, &req_header);
        } else {
            send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>", req_header.is_keep_alive);
        }
    }
}