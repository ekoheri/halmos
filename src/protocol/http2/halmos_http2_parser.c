#include "halmos_http2_parser.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_http_multipart.h"
#include "halmos_http2_huffman.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

// --- IMPLEMENTASI HPACK STATE (MENGGUNAKAN STRUCT LAMA KAMU) ---

// Sesuai RFC 7541: Daftar Static Table (1-61)
static const struct { const char *n; const char *v; } static_table[] = {
    {NULL, NULL}, // Index 0 (Padding)
    {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
    {":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"}, {":status", "200"},
    {":status", "204"}, {":status", "206"}, {":status", "304"}, {":status", "400"},
    {":status", "404"}, {":status", "500"}, {"accept-charset", ""}, {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""},
    {"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
    {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
    {"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""},
    {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""}, {"from", ""}, {"host", ""},
    {"if-match", ""}, {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""},
    {"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""}, {"location", ""},
    {"max-forwards", ""}, {"proxy-authenticate", ""}, {"proxy-authorization", ""}, {"range", ""},
    {"referer", ""}, {"refresh", ""}, {"retry-after", ""}, {"server", ""}, {"set-cookie", ""},
    {"strict-transport-security", ""}, {"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""},
    {"via", ""}, {"www-authenticate", ""}
};

/**
 * hpack_get_header: Ambil data dari static (1-61) atau dynamic (>61)
 */
bool hpack_get_header(HTTP2Session *session, uint32_t index, const char **name, const char **value) {
    // 1. Cek Static Table (1-61)
    if (index >= 1 && index <= 61) {
        *name = static_table[index].n;
        *value = static_table[index].v;
        return true;
    }

    // 2. Cek Dynamic Table (Index 62 ke atas)
    if (session && session->dyn_table.count > 0) {
        // Rumus RFC: Indeks 62 adalah entri paling baru (index 0 di array kita)
        // Indeks 63 adalah entri sebelumnya (index 1 di array kita), dst.
        uint32_t dyn_idx = index - 62;
        
        if (dyn_idx < session->dyn_table.count) {
            *name = session->dyn_table.entries[dyn_idx].name;
            *value = session->dyn_table.entries[dyn_idx].value;
            
            // Debugging (Opsional, matikan jika sudah stabil)
            // printf("[H2-DEBUG] Hit Dynamic Index %u -> %s: %s\n", index, *name, *value);
            return true;
        }
    }

    // Jika sampai sini, berarti indeks tidak valid atau tabel kosong
    return false;
}

/**
 * hpack_dynamic_table_add: Tambah entri & hitung entry_size sesuai struct-mu
 */
void hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value) {
    if (!session || !name || !value) return;

    if (session->dyn_table.entries == NULL) {
        //fprintf(stderr, "[H2-ERR] Dynamic Table entries is NULL!\n");
        return; 
    }
    
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    uint32_t new_entry_size = (uint32_t)(name_len + value_len + 32);

    // FIFO: Geser entri lama ke belakang
    // Halmos menggunakan limit 128 entri untuk saat ini
    if (session->dyn_table.count < 128) {
        for (int i = session->dyn_table.count; i > 0; i--) {
            session->dyn_table.entries[i] = session->dyn_table.entries[i-1];
        }
        
        // Isi entri baru di posisi paling depan (index 0 tabel dinamis = index 62 HPACK)
        session->dyn_table.entries[0].name = strdup(name);
        session->dyn_table.entries[0].value = strdup(value);
        session->dyn_table.entries[0].entry_size = new_entry_size;
        
        session->dyn_table.count++;
        // Kamu juga bisa mengupdate session->dyn_table.current_size di sini jika ada fieldnya
    }
}

/**
 * Membedah 9-byte header frame HTTP/2.
 */
bool http2_parse_frame_header(const unsigned char *buf, HTTP2FrameHeader *out) {
    if (!buf || !out) return false;
    out->length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
    out->type = buf[3];
    out->flags = buf[4];
    out->stream_id = ((buf[5] & 0x7F) << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8];
    return true;
}

/**
 * Membaca integer dari payload HPACK
 */
static uint32_t hpack_decode_int(const unsigned char **pos, const unsigned char *end, uint8_t prefix_mask) {
    if (*pos >= end) return 0;
    const unsigned char *p = *pos;
    uint32_t res = (*p++) & prefix_mask;

    if (res < prefix_mask) {
        *pos = p;
        return res;
    }

    uint32_t shift = 0;
    while (p < end) {
        unsigned char b = *p++;
        res += (uint32_t)(b & 127) << shift;
        if (!(b & 128)) break;
        shift += 7;
        if (shift > 28) { // Proteksi overflow
            //fprintf(stderr, "  [H2-ERR] HPACK Integer Overflow!\n");
            break; 
        }
    }
    *pos = p;
    return res;
}

/**
 * hpack_decode_string: Menangani string literal atau Huffman.
 * Ditambahkan proteksi NULL check untuk Chrome stability.
 */
static char* hpack_decode_string(const unsigned char **pos, const unsigned char *end) {
    if (*pos >= end) return NULL;
    
    uint8_t first_byte = **pos;
    bool is_huffman = (first_byte & 0x80) != 0;
    uint32_t len = hpack_decode_int(pos, end, 0x7F);

    if (len > 10240 || *pos + len > end) {
        // Jika length tidak masuk akal, kemungkinan besar parser tersesat
        return NULL;
    }

    char *str = NULL;
    if (is_huffman) {
        str = http2_huffman_decode(*pos, len);
    } else {
        str = malloc(len + 1);
        if (str) { 
            memcpy(str, *pos, len); 
            str[len] = '\0'; 
        }
    }
    *pos += len;
    return str;
}

static void process_literal_header_with_name(const char *name, const char *value, RequestHeader *req) {
    if (!name || !value) return;

    if (strcasecmp(name, "content-type") == 0) {
        if (req->content_type) free(req->content_type);
        req->content_type = strdup(value);
    } else if (strcasecmp(name, "content-length") == 0) {
        req->content_length = strtol(value, NULL, 10);
    } else if (strcasecmp(name, "cookie") == 0) {
        if (req->cookie_data == NULL) {
            req->cookie_data = strdup(value);
        } else {
            char *old = req->cookie_data;
            asprintf(&req->cookie_data, "%s; %s", old, value);
            free(old);
        }
    } else if (strcasecmp(name, ":authority") == 0 || strcasecmp(name, "host") == 0) {
        if (req->host) free(req->host);
        req->host = strdup(value);
    } else if (strcasecmp(name, ":method") == 0) {
        strncpy(req->method, value, sizeof(req->method) - 1);
    } else if (strcasecmp(name, ":path") == 0) {
        if (req->uri) free(req->uri);
        req->uri = strdup(value);
    }
}

static void process_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req) {
    if (index == 0) return;
    
    const char *name = NULL;
    const char *value = NULL;

    // Sekarang mendukung Static Table (1-61) dan Dynamic Table (>61)
    if (hpack_get_header(session, index, &name, &value)) {
        
        // TRACE: Supaya kelihatan di log index mana yang kena
        //fprintf(stderr, "[H2-HPACK-TRACE] Kategori 1 (Indexed) -> Index: %u, Name: %s, Value: %s\n", 
        //        index, name ? name : "NULL", value ? value : "NULL");

        // 1. Gunakan fungsi with_name untuk semua header umum (content-type, content-length, dll)
        // Ini lebih aman karena menangani string name secara case-insensitive
        process_literal_header_with_name(name, value, req);
        
        // 2. Mapping Pseudo-Headers & Specific Logic (Tetap perlu strcmp untuk kecepatan)
        if (name) {
            if (strcmp(name, ":method") == 0) {
                strncpy(req->method, value, sizeof(req->method)-1);
            } else if (strcmp(name, ":path") == 0) {
                if(req->uri) free(req->uri); 
                req->uri = strdup(value);
            } else if (strcmp(name, ":authority") == 0) {
                if(req->host) free(req->host); 
                req->host = strdup(value);
            } else if (strcmp(name, ":scheme") == 0) {
                req->is_tls = (strcmp(value, "https") == 0);
            } else if (strcasecmp(name, "cookie") == 0) {
                if (req->cookie_data == NULL) {
                    req->cookie_data = strdup(value);
                } else {
                    // Gabungkan dengan pemisah "; "
                    char *old = req->cookie_data;
                    if (asprintf(&req->cookie_data, "%s; %s", old, value) != -1) {
                        free(old);
                    }
                }
            }
        }
    } /*else {
        fprintf(stderr, "[H2-HPACK-ERR] Gagal ambil header untuk Index: %u\n", index);
    }*/
}

/**
 * Huffman Decoder (Trace enabled)
 */
char* http2_huffman_decode(const unsigned char *src, size_t len) {
    if (!src || len == 0) return NULL;
    
    // Alokasi memori (Huffman HTTP/2 maksimal mengembang ~1.6x)
    // len * 2 + 1 sudah sangat aman.
    char *dest = malloc(len * 2 + 1); 
    if (!dest) return NULL;

    size_t out_pos = 0;
    uint16_t state = 0;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t b = src[i];
        
        // High nibble (4-bit pertama)
        const nghttp2_huff_decode *t1 = &huff_decode_table[state][b >> 4];
        if (t1->flags & NGHTTP2_HUFF_SYM) {
            dest[out_pos++] = t1->sym;
        }
        state = t1->fstate;

        // Low nibble (4-bit terakhir)
        const nghttp2_huff_decode *t2 = &huff_decode_table[state][b & 0x0f];
        if (t2->flags & NGHTTP2_HUFF_SYM) {
            dest[out_pos++] = t2->sym;
        }
        state = t2->fstate;
    }
    
    dest[out_pos] = '\0';

    // Jika terjadi anomali (state tidak kembali ke awal/final), 
    // namun tetap menghasilkan string, kita tetap kembalikan stringnya 
    // agar sistem tidak crash/null.
    return dest;
}

/**
 * http2_hpack_decode - DENGAN DEBUG TRACE LENGKAP
 */

 /**
 * http2_hpack_decode
 * Membedah payload HEADERS frame dan memetakan ke struct RequestHeader Halmos.
 */
bool http2_hpack_decode(HTTP2Session *session, HTTP2Stream *stream, const unsigned char *payload, size_t len) {
    if (!payload || len == 0) return false;
    
    const unsigned char *pos = payload;
    const unsigned char *end = payload + len;
    RequestHeader *req = &stream->http1_compat;

    // Bersihkan method sebelum mulai
    memset(req->method, 0, sizeof(req->method));
    
    // 1. CHROME/FIREFOX PRIORITY SKIP
    // Browser sering menyisipkan 5 byte data prioritas (E-bit + Stream Dep + Weight)
    if (len > 5 && (payload[0] & 0x7F) == 0 && payload[1] == 0 && payload[2] == 0) {
        pos += 5;
    }

    pthread_mutex_lock(&session->hpack_lock);

    while (pos < end) {
        uint8_t b = *pos;
        
        // KATEGORI 1: Indexed Header Field (1xxx xxxx)
        if (b & 0x80) { 
            uint32_t index = hpack_decode_int(&pos, end, 0x7F);
            process_indexed_header(session, index, req);
        } 
        // KATEGORI 2: Literal Header Field with Incremental Indexing (01xx xxxx)
        else if ((b & 0xC0) == 0x40) { 
            uint32_t index = hpack_decode_int(&pos, end, 0x3F);
            char *name = NULL;
            if (index == 0) {
                name = hpack_decode_string(&pos, end);
            } else {
                const char *s_name, *s_value;
                if (hpack_get_header(session, index, &s_name, &s_value)) name = strdup(s_name);
            }
            char *value = hpack_decode_string(&pos, end);
            
            if (name && value) {
                // PERBAIKAN: Gunakan pengecekan nama, bukan cuma index
                //fprintf(stderr, "[H2-PARSER-TRACE] Found Header -> %s: %s\n", name, value);
                process_literal_header_with_name(name, value, req);
                hpack_dynamic_table_add(session, name, value);
            }
            if (name) free(name);
            if (value) free(value);
        }
        // KATEGORI 3: Dynamic Table Size Update (001x xxxx)
        else if ((b & 0xE0) == 0x20) { 
            hpack_decode_int(&pos, end, 0x1F); 
        }
        // KATEGORI 4: Literal Header Field Without Indexing
        else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
            uint32_t index = hpack_decode_int(&pos, end, 0x0F);
            char *name = NULL;
            if (index == 0) {
                name = hpack_decode_string(&pos, end);
            } else {
                const char *s_name, *s_value;
                if (hpack_get_header(session, index, &s_name, &s_value)) name = strdup(s_name);
            }
            char *value = hpack_decode_string(&pos, end);
            
            if (name && value) {
                // TAMBAHAN FPRINTF UNTUK TRACE
                //fprintf(stderr, "[H2-HPACK-TRACE] Kategori 4 -> Name: %s, Value: %s (Index: %u)\n", name, value, index);
                
                // PERBAIKAN: Gunakan _with_name agar string-nya dicek
                process_literal_header_with_name(name, value, req);
            }
            
            if (name) free(name);
            if (value) free(value);
        }
        else {
            pos++;
        }
    }

    pthread_mutex_unlock(&session->hpack_lock);

    // --- HALMOS LOGIC BRIDGE: SINKRONISASI URI, QUERY, & PATH_INFO ---
    
    if (req->uri) {
        // 1. Ekstrak Query String jika ada (misal: /test.php?id=1)
        char *qs = strchr(req->uri, '?');
        if (qs) {
            *qs = '\0';             // Putus string di tanda '?'
            req->query_string = qs + 1;
        }

        // 2. Deteksi Path Info untuk Backend (PHP/Rust/Python)
        // Kita cari titik ekstensi untuk memisahkan file utama dengan path tambahan
        const char *exts_list[] = {".php", ".rs", ".py", ".sh"};
        req->path_info = NULL; 
        for (int i = 0; i < 4; i++) {
            char *ptr_ext = strcasestr(req->uri, exts_list[i]);
            if (ptr_ext) {
                size_t elen = strlen(exts_list[i]);
                if (*(ptr_ext + elen) == '/') {
                    req->path_info = ptr_ext + elen;
                }
                break;
            }
        }

        // 3. Integrasi VHost & Routing
        if (req->host) {
            VHostEntry *vh = (VHostEntry *)http_vhost_get_context(req->host);
            req->vhost_context = vh;

            // Arahkan ke index default jika kosong
            if (req->uri[0] == '\0' || strcmp(req->uri, "/") == 0) {
                if (req->uri && req->uri != req->route_result) free(req->uri);
                
                snprintf(req->route_result, sizeof(req->route_result), "/index.html");
                req->uri = req->route_result; 
                req->path_info = NULL;
            }

            // Jalankan pencocokan Route (Regex/Alias) jika ada
            RouteTable *match = http_route_match(vh, req->uri);
            if (match) {
                char t_query[256], t_path[256];
                char *old_uri = req->uri; // Simpan alamat lama hasil HPACK parser
                
                // Simpan hasil transformasi URI langsung ke dalam route_result
                http_route_apply_logic(match, old_uri, req->route_result, t_query, t_path);
                
                // Sekarang req->uri aman menunjuk ke buffer fisik
                req->uri = req->route_result;
                
                // HANYA free jika old_uri adalah hasil strdup (bukan menunjuk ke route_result)
                if (old_uri && old_uri != req->route_result) {
                    free(old_uri);
                }
                
                // SINKRONISASI QUERY STRING
                if (t_query[0] != '\0') {
                    char *new_qs = strchr(req->uri, '?');
                    if (new_qs) {
                        *new_qs = '\0';
                        req->query_string = new_qs + 1;
                    } else {
                        // Gunakan query_string_buffer yang ada di struct
                        strncpy(req->query_string_buffer, t_query, sizeof(req->query_string_buffer) - 1);
                        req->query_string = req->query_string_buffer;
                    }
                }
            }
        }
        
        // Sinkronisasi pointer directory untuk module statis
        req->directory = req->uri;
    }

    // Validasi akhir: Request dianggap valid jika Method dan URI sudah terisi
    req->is_valid = (req->method[0] != '\0' && req->uri != NULL);
    
    return req->is_valid;
}

void http2_parser_free_memory(HTTP2Stream *stream) {
    if (!stream) return;
    RequestHeader *req = &stream->http1_compat;

    #define IS_IN_ROUTE_RESULT(p) ((char*)(p) >= (char*)req->route_result && (char*)(p) < (char*)(req->route_result + sizeof(req->route_result)))

    if (req->uri && !IS_IN_ROUTE_RESULT(req->uri)) {
        free(req->uri);
        req->uri = NULL;
    }
    if (req->host && !IS_IN_ROUTE_RESULT(req->host)) {
        free(req->host);
        req->host = NULL;
    }
    if (req->content_type) {
        free(req->content_type);
        req->content_type = NULL;
    }
    if (req->cookie_data) {
        free(req->cookie_data);
        req->cookie_data = NULL;
    }

    // Panggil fungsi FREE yang ada di HTTP/1 (halmos_http_multipart.c)
    if (req->parts) {
        http_multipart_free_parts(req->parts, req->parts_count);
        req->parts = NULL; // Proteksi double-free
        req->parts_count = 0;
    }

    if (req->body_data) {
        free(req->body_data);
        req->body_data = NULL;
    }

    #undef IS_IN_ROUTE_RESULT
}