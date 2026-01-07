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

//Tambahan untuk library zerro-copy
#include <sys/sendfile.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>  // Wajib untuk fungsi stat() dan makro S_ISREG
#include <sys/types.h> // Mendukung definisi tipe data sistem

//// Fungsi untuk membersihkan path dan mencegah traversal
#include <limits.h>

#include "../include/http.h"
#include "../include/config.h"
#include "../include/log.h"

#define BUFFER_SIZE 1024

extern Config config;

// int request_buffer_size = BUFFER_SIZE * 4;
// int response_buffer_size = BUFFER_SIZE * 8;

char *sanitize_path(const char *root, const char *uri) {
    char full_path[PATH_MAX];
    char resolved_path[PATH_MAX];

    // 1. Gabungkan root dan uri mentah
    snprintf(full_path, sizeof(full_path), "%s/%s", root, uri);

    // 2. Gunakan realpath() untuk menyelesaikan ".." dan "."
    // realpath akan mengubah "/var/www/html/../etc/passwd" menjadi "/etc/passwd"
    if (realpath(full_path, resolved_path) == NULL) {
        return NULL; // Path tidak valid atau file tidak ada
    }

    // 3. KUNCI KEAMANAN: Pastikan resolved_path masih dimulai dengan root
    // Jika tidak, berarti user mencoba melompat keluar dari folder web
    if (strncmp(root, resolved_path, strlen(root)) != 0) {
        return NULL; // Upaya bypass terdeteksi!
    }

    return strdup(resolved_path);
}

void url_decode(char *src) {
    char *dst = src;
    while (*src) {
        if (*src == '+') {
            // Dalam URL, '+' biasanya berarti spasi
            *dst = ' ';
        } else if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            // Ambil 2 digit hex (misal %20)
            char hex[3] = { src[1], src[2], '\0' };
            *dst = (char)strtol(hex, NULL, 16);
            src += 2;
        } else {
            *dst = *src;
        }
        src++;
        dst++;
    }
    *dst = '\0';
}

void parse_multipart_body(RequestHeader *req) {
    if (!req->content_type || !req->body_data || req->body_length == 0) return;

    // 1. Ekstrak Boundary dari Content-Type
    char *boundary_ptr = strstr(req->content_type, "boundary=");
    if (!boundary_ptr) return;
    
    char boundary[256];
    snprintf(boundary, sizeof(boundary), "--%s", boundary_ptr + 9);
    size_t boundary_len = strlen(boundary);

    char *current_pos = (char *)req->body_data;
    size_t remaining_len = req->body_length;

    // Alokasi awal untuk 10 parts (bisa di-realloc jika kurang)
    req->parts = malloc(sizeof(MultipartPart) * 10);
    req->parts_count = 0;

    while (remaining_len > boundary_len) {
        // Cari posisi boundary
        char *part_start = memmem(current_pos, remaining_len, boundary, boundary_len);
        if (!part_start) break;

        // Header part dimulai setelah boundary + \r\n
        char *header_start = part_start + boundary_len + 2;
        
        // Cari akhir dari header part (\r\n\r\n)
        char *header_end = memmem(header_start, remaining_len - (header_start - (char*)req->body_data), "\r\n\r\n", 4);
        if (!header_end) break;

        // --- INI BAGIAN BARU (Taruh tepat di sini) ---
        // Cek apakah laci sudah penuh (0-9 sudah terisi, sekarang mau isi yang ke-10)
        if (req->parts_count >= 10 && req->parts_count % 10 == 0) {
            size_t new_size = sizeof(MultipartPart) * (req->parts_count + 10);
            MultipartPart *temp = realloc(req->parts, new_size);
            if (!temp) {
                write_log("Security: Gagal menambah kapasitas Multipart (Out of Memory)");
                break; 
            }
            req->parts = temp;
        }
        // --------------------------------------------

        MultipartPart *p = &req->parts[req->parts_count];
        memset(p, 0, sizeof(MultipartPart));

        // 2. Ekstrak 'name' dan 'filename' dari header part
        char *h_buf = strndup(header_start, header_end - header_start);
        char *n_ptr = strstr(h_buf, "name=\"");
        if (n_ptr) {
            char *n_end = strchr(n_ptr + 6, '\"');
            if (n_end) p->name = strndup(n_ptr + 6, n_end - (n_ptr + 6));
        }
        char *f_ptr = strstr(h_buf, "filename=\"");
        if (f_ptr) {
            char *f_end = strchr(f_ptr + 10, '\"');
            if (f_end) p->filename = strndup(f_ptr + 10, f_end - (f_ptr + 10));
        }
        free(h_buf);

        // 3. Tentukan letak DATA
        char *data_start = header_end + 4;
        
        // Cari boundary berikutnya untuk menentukan akhir data ini
        char *next_boundary = memmem(data_start, remaining_len - (data_start - (char*)req->body_data), boundary, boundary_len);
        
        if (next_boundary) {
            // data_len adalah jarak antara data_start dan boundary berikutnya (dikurangi \r\n)
            // 1. Hitung panjang data asli (tanpa \r\n sebelum boundary)
            p->data_len = (size_t)((next_boundary - 2) - data_start);

            // 2. KUNCI: Alokasikan data_len + 1 (untuk null terminator)
            p->data = malloc(p->data_len + 1);
            
            if (p->data) {
                // 3. Salin hanya data aslinya (sejauh data_len)
                memcpy(p->data, data_start, p->data_len);
                
                // 4. Tambahkan terminator di byte terakhir yang kita pesan tadi
                // Ini menjaga agar p->data tetap aman jika diakses sebagai string
                ((char*)p->data)[p->data_len] = '\0';
            }
            
            req->parts_count++;
            
            // Geser posisi pembacaan
            remaining_len -= (next_boundary - current_pos);
            current_pos = next_boundary;
        } else {
            break;
        }
    }
}

void trim_right(char *s) {
    if (!s) return;
    int len = strlen(s);
    while (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n' || isspace(s[len-1]))) {
        s[len-1] = '\0';
        len--;
    }
}

RequestHeader parse_request_line(char *request, size_t total_received) {
    RequestHeader req = {0};
    req.is_valid = false;

    // 1. Cari batas Header (\r\n\r\n)
    char *header_end = strstr(request, "\r\n\r\n");
    if (!header_end) return req;

    // Sementara kasih warning jika headernya terlalu besar. 
    // Kedepan header ini harus dilimit untuk menghindari serangan Buffer Overflow
    size_t header_len = header_end - request;
    if (header_len > 8192) { // Contoh limit 8KB
        write_log("Warning: Header too large!");
    }


    // 2. Parsing Baris Pertama (Method & URI)
    char *first_line_end = strstr(request, "\r\n");
    if (first_line_end) {
        char *line = strndup(request, first_line_end - request);
        char *m = strtok(line, " ");
        char *u = strtok(NULL, " ");
        char *v = strtok(NULL, " ");

        if (m && u) {
            strncpy(req.method, m, sizeof(req.method)-1);
            if (v) strncpy(req.http_version, v, sizeof(req.http_version)-1);

            // Pisahkan Query String
            char *q = strchr(u, '?');
            if (q) {
                req.query_string = strdup(q + 1);
                url_decode(req.query_string); // Decode query string
                *q = '\0';
            } else {
                req.query_string = strdup("");
            }
            
            // Simpan URI dasar
            req.uri = strdup(u[0] == '/' && u[1] == '\0' ? "index.html" : u);
            url_decode(req.uri); // Decode URI (penting jika nama file ada spasi)
            req.is_valid = true;
        }
        free(line);
    }

    // 3. Parsing Headers (Content-Length & Type)
    char *search_ptr = strstr(request, "\r\n") + 2;
    while (search_ptr < header_end) {
        char *next_line = strstr(search_ptr, "\r\n");
        if (!next_line || next_line > header_end) break;

        if (strncasecmp(search_ptr, "Content-Length: ", 16) == 0) {
            req.content_length = atoi(search_ptr + 16);
        } else if (strncasecmp(search_ptr, "Content-Type: ", 14) == 0) {
            req.content_type = strndup(search_ptr + 14, next_line - (search_ptr + 14));
            trim_right(req.content_type);
        } else if (strncasecmp(search_ptr, "Upgrade: websocket", 18) == 0) {
            req.is_upgrade = true;
        }
        search_ptr = next_line + 2;
    }

    // 4. Salin Body (Binary Safe dengan Null-Terminator)
    if (req.content_length > 0) {
        char *body_start = header_end + 4;
        size_t bytes_already_in_buffer = total_received - (body_start - request);
        
        // Alokasikan + 1 untuk safety null terminator
        req.body_data = malloc(req.content_length + 1); 
        if (req.body_data) {
            size_t to_copy = (bytes_already_in_buffer > (size_t)req.content_length) ? (size_t)req.content_length : bytes_already_in_buffer;
            
            memcpy(req.body_data, body_start, to_copy);
            req.body_length = to_copy;
            
            // Inisialisasi sisa memori dengan 0 agar tidak berisi data sampah
            // saat nanti kita melakukan recv() tambahan di web_server.c
            memset((char*)req.body_data + to_copy, 0, (req.content_length + 1) - to_copy);
            
            ((char*)req.body_data)[to_copy] = '\0';
        }
    }

    // 5. Jika Multipart, panggil parser khusus
    // Bagian ini dipindahkan ke web_server.c
    /*if (req.content_type && strstr(req.content_type, "multipart/form-data")) {
        parse_multipart_body(&req);
    }*/

    return req;
}

void free_request_header(RequestHeader *req) {
    if (req == NULL) return;

    // 1. Bebaskan memori dinamis (Pointer)
    if (req->directory)      free(req->directory);
    if (req->uri)            free(req->uri);
    if (req->query_string)   free(req->query_string);
    if (req->path_info)      free(req->path_info);
    if (req->body_data)      free(req->body_data); // void* aman di-free
    if (req->content_type)   free(req->content_type);

    // 2. Bebaskan Nested WebSocket Info
    if (req->ws.key)         free(req->ws.key);
    if (req->ws.protocol)    free(req->ws.protocol);

    // 3. Bebaskan Multipart (Looping)
    if (req->parts) {
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].name)         free(req->parts[i].name);
            if (req->parts[i].filename)     free(req->parts[i].filename);
            if (req->parts[i].data)         free(req->parts[i].data);
            if (req->parts[i].content_type) free(req->parts[i].content_type);
        }
        free(req->parts);
    }

    // 4. KUNCI KEAMANAN: Bersihkan seluruh struct
    // Ini akan me-reset method[16], http_version[16], 
    // is_valid, dan semua pointer yang sudah di-free tadi ke 0/NULL.
    memset(req, 0, sizeof(RequestHeader));
}

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

/**
 * Mengirimkan respon HTTP yang datanya berasal dari memori (bukan file).
 * Cocok untuk halaman error, status sederhana, atau API response kecil.
 */
void send_mem_response(int sock, int code, const char *msg, const char *body) {
    char header[512];
    
    // 1. Susun HTTP Header
    // Kita gunakan Connection: close karena ini biasanya untuk pesan error/akhir
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Server: Halmos-Core\r\n"
        "Connection: close\r\n\r\n",
        code, msg, strlen(body));
    
    // 2. Kirim Header
    send(sock, header, h_len, 0);
    
    // 3. Kirim Body
    send(sock, body, strlen(body), 0);
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

bool save_uploaded_file(MultipartPart *part, const char *destination_folder) {
    if (!part || !part->filename || !part->data) return false;

    char full_path[PATH_MAX];
    // Pastikan folder tujuan ada dan aman
    snprintf(full_path, sizeof(full_path), "%s/%s", destination_folder, part->filename);

    FILE *fp = fopen(full_path, "wb");
    if (!fp) {
        write_log("Gagal membuka file untuk penulisan: %s", full_path);
        return false;
    }

    size_t written = fwrite(part->data, 1, part->data_len, fp);
    fclose(fp);

    if (written == part->data_len) {
        write_log("File berhasil disimpan: %s (%zu bytes)", full_path, written);
        return true;
    }

    return false;
}

void handle_get_request(int sock_client, RequestHeader *req) {
    // Sanitasi Path (Pindahan dari kode lama)
    char *safe_file_path = sanitize_path(config.document_root, req->uri);

    if (safe_file_path == NULL) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>");
        return;
    }

    struct stat st;
    if (stat(safe_file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_mem_response(sock_client, 404, "Not Found", "<h1>404 Not Found</h1>");
        free(safe_file_path);
        return;
    }

    // Ambil MIME Type
    const char *mime = get_mime_type(req->uri);
    
    // Siapkan Header
    char header[1024];
    int h_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: Halmos-Core\r\n"
        "Connection: keep-alive\r\n\r\n",
        mime, st.st_size);

    send(sock_client, header, h_len, 0);

    // Kirim File dengan Zero-Copy (Looping untuk Non-Blocking)
    int fd = open(safe_file_path, O_RDONLY);
    if (fd != -1) {
        off_t offset = 0;
        size_t remaining = st.st_size;
        while (remaining > 0) {
            ssize_t sent = sendfile(sock_client, fd, &offset, remaining);
            if (sent <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(1000); // Tunggu buffer socket kosong
                    continue;
                }
                break; // Error atau koneksi terputus
            }
            remaining -= sent;
        }
        close(fd);
    }

    free(safe_file_path);
}

void handle_post_request(int sock_client, RequestHeader *req) {
    // Jika ada data multipart (Upload file atau Form)
    if (req->parts_count > 0) {
        bool upload_success = false;
        
        for (int i = 0; i < req->parts_count; i++) {
            if (req->parts[i].filename) {
                // Simpan file ke folder uploads
                if (save_uploaded_file(&req->parts[i], "uploads")) {
                    upload_success = true;
                }
            }
        }

        if (upload_success) {
            send_mem_response(sock_client, 201, "Created", "<h1>File Berhasil Diupload!</h1>");
        } else {
            send_mem_response(sock_client, 200, "OK", "<h1>Form Data Diterima</h1>");
        }
    } 
    // Jika hanya POST body biasa (Plain text / JSON)
    else if (req->body_data) {
        write_log("Data POST diterima: %s", (char*)req->body_data);
        send_mem_response(sock_client, 200, "OK", "<h1>Data POST Diterima</h1>");
    } else {
        send_mem_response(sock_client, 400, "Bad Request", "<h1>Empty POST body</h1>");
    }
}

void handle_method(int sock_client, RequestHeader req_header) {
    // Jalur WebSocket
    if (config.secure_application && req_header.is_upgrade) {
        // ... logika websocket ...
        return;
    }

    // Jalur GET (File Statis)
    if (strcmp(req_header.method, "GET") == 0) {
        handle_get_request(sock_client, &req_header); // Pindah ke sini
    } 
    // Jalur POST (Upload/Data)
    else if (strcmp(req_header.method, "POST") == 0) {
        handle_post_request(sock_client, &req_header);
    } 
    else {
        send_mem_response(sock_client, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>");
    }
}