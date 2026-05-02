#include "halmos_http2_response.h"
#include "halmos_http1_response.h"
#include "halmos_http2_manager.h"
#include "halmos_global.h"
#include "halmos_http_utils.h"
#include "halmos_fcgi.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>      // Untuk open, O_RDONLY
#include <sys/stat.h>   // Untuk stat, struct stat, S_ISDIR
#include <limits.h>     // Untuk PATH_MAX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>     // Untuk AF_UNIX

void http2_response_routing_bridge(HTTP2Session *session, HTTP2Stream *stream) {
    RequestHeader *req = &stream->http1_compat;
    
    // 1. IDENTIFIKASI BACKEND (Gunakan logika yang sama dengan HTTP/1.1 Mas)
    int backend_type = -1; 
    if (has_extension(req->uri, req->path_info, ".php")) { 
        backend_type = 0; // PHP
    } 
    else if (has_extension(req->uri, req->path_info, config.rust.ext)) { 
        backend_type = 1; // Rust
    } 
    else if (has_extension(req->uri, req->path_info, config.python.ext)) { 
        backend_type = 2; // Python
    }

    // 2. JALUR FASTCGI
    if (backend_type != -1) {
        // --- INI SOLUSINYA: KITA BUAT SOCK_CLIENT PALSU (VIRTUAL) ---
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            
            // Mas kasih sv[1] ke FastCGI API. 
            // Si FastCGI akan mengira ini sock_client asli!
            fcgi_api_request_stream(req, sv[1], backend_type, req->body_data, req->content_length);
            close(sv[1]); // Tutup ujung tulis

            // Nah, di sini tugas HTTP/2 (Penerjemah)
            // Baca teks dari sv[0], bungkus ke Frame, kirim ke session->fd
            unsigned char proxy_buf[16384];
            ssize_t n;
            bool headers_done = false;
            bool body_found = false;

            while ((n = read(sv[0], proxy_buf, sizeof(proxy_buf))) > 0) {
                if (!body_found) {
                    // Cari pembatas header FastCGI (\r\n\r\n)
                    char *divider = strstr((char*)proxy_buf, "\r\n\r\n");
                    
                    if (divider) {
                        body_found = true;
                        // 1. Kirim Header Biner H2 (Hanya sekali!)
                        if (!headers_done) {
                            http2_response_send_header(session, stream, 200);
                            headers_done = true;
                        }

                        // 2. Kirim sisanya (Body saja)
                        char *body_data = divider + 4;
                        size_t body_len = n - (body_data - (char*)proxy_buf);
                        if (body_len > 0) {
                            http2_response_send_data(session, stream, body_data, body_len, false);
                        }
                    }
                    // Jika divider tidak ketemu, data ini kita BUANG 
                    // (karena ini adalah raw header HTTP/1.1 yang tidak dibutuhkan H2)
                } else {
                    // Sudah di jalur body, kirim semua sebagai DATA frame
                    http2_response_send_data(session, stream, proxy_buf, (size_t)n, false);
                }
            }
            // Tutup Stream dengan END_STREAM
            http2_response_send_data(session, stream, NULL, 0, true);
            close(sv[0]);
        }
        return;
    }

    // 3. JALUR FILE STATIS (Logic asli Mas Eko)
    VHostEntry *vh = (VHostEntry *)req->vhost_context;
    const char *active_root = (vh && vh->root[0] != '\0') ? vh->root : config.document_root;

    char *safe_path = sanitize_path(active_root, req->uri);
    struct stat st;

    // Cek keberadaan file
    if (!safe_path || stat(safe_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        http2_response_send_header(session, stream, 404);
        http2_response_send_data(session, stream, "Not Found", 9, true);
        if(safe_path) free(safe_path);
        return;
    }

    // 4. KIRIM HEADER (Hanya untuk File Statis)
    // Ingat: Untuk PHP, Header dikirim oleh http2_handle_fastcgi setelah dpt response dari PHP-FPM
    http2_response_send_header(session, stream, 200);

    // 5. KIRIM FILE (Logika Buffer & h2_send_frame)
    int fd = open(safe_path, O_RDONLY);
    if (fd == -1) {
        http2_response_send_data(session, stream, "Forbidden", 9, true);
    } else {
        unsigned char buffer[16384];
        ssize_t n;
        size_t total_sent = 0;
        size_t file_size = (size_t)st.st_size;

        if (file_size == 0) {
            http2_response_send_data(session, stream, NULL, 0, true);
        } else {
            while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
                total_sent += n;
                // is_end true jika byte yang dibaca sudah mencapai akhir file
                bool is_end = (total_sent >= file_size);
                http2_response_send_data(session, stream, buffer, (size_t)n, is_end);
            }
        }
        close(fd);
    }
    
    if(safe_path) free(safe_path);
}

void http2_response_send_header(HTTP2Session *session, HTTP2Stream *stream, int status_code) {
    unsigned char hpack_buf[256];
    int pos = 0;

    // 1. Status Code (Sangat aman, pakai Indexed Header)
    switch(status_code) {
        case 200: hpack_buf[pos++] = 0x88; break; // :status: 200
        case 404: hpack_buf[pos++] = 0x8D; break; // :status: 404
        default:  hpack_buf[pos++] = 0x8F; break; // :status: 500
    }

    // 2. Content-Type (Pakai Literal Header Field with Incremental Indexing - Indexed Name)
    // Rumusnya: 0x40 | Index. Index 'content-type' adalah 31 (0x1f).
    // Jadi: 0x40 | 0x1f = 0x5F.
    hpack_buf[pos++] = 0x5F; 

    const char *mime = get_mime_type(stream->http1_compat.uri);
    size_t mime_len = strlen(mime);

    // 3. String Length (Tanpa Huffman)
    hpack_buf[pos++] = (unsigned char)mime_len; 
    
    // 4. String Value
    memcpy(&hpack_buf[pos], mime, mime_len);
    pos += mime_len;

    // KIRIM: Type 0x01 (HEADERS), Flag 0x04 (END_HEADERS)
    h2_send_frame(session->fd, session->is_tls, 0x01, 0x04, stream->stream_id, hpack_buf, (uint32_t)pos);
}

void http2_response_send_data(HTTP2Session *session, HTTP2Stream *stream, const void *data, size_t len, bool is_end) {
    // Type 0x00 (DATA), Flag 0x01 (END_STREAM jika is_end true)
    uint8_t flags = is_end ? 0x01 : 0x00;
    h2_send_frame(session->fd, session->is_tls, 0x00, flags, stream->stream_id, data, (uint32_t)len);
}


