#include "halmos_http2_parser.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_http_multipart.h"
#include "halmos_http2_huffman.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

typedef struct {
    const char *name;
    const char *value;
} HPACKStaticEntry;

// Sesuai RFC 7541: Daftar Static Table (1-61)
static const HPACKStaticEntry static_table[] = {
    {NULL, NULL}, 
    {":authority", ""}, 
    {":method", "GET"}, 
    {":method", "POST"}, 
    {":path", "/"},
    {":path", "/index.html"}, 
    {":scheme", "http"}, 
    {":scheme", "https"}, 
    {":status", "200"},
    {":status", "204"}, 
    {":status", "206"}, 
    {":status", "304"}, 
    {":status", "400"},
    {":status", "404"}, 
    {":status", "500"}, 
    {"accept-charset", ""}, 
    {"accept-encoding", "gzip, deflate"},
    {".accept-language", ""}, 
    {"accept-ranges", ""}, 
    {"accept", ""}, 
    {"access-control-allow-origin", ""},
    {"age", ""}, 
    {"allow", ""}, 
    {"authorization", ""}, 
    {"cache-control", ""},
    {"content-disposition", ""}, 
    {"content-encoding", ""}, 
    {"content-language", ""}, 
    {"content-length", ""},
    {"content-location", ""}, 
    {"content-range", ""}, 
    {"content-type", ""}, {"cookie", ""},
    {"date", ""}, 
    {"etag", ""}, 
    {"expect", ""}, 
    {"expires", ""}, 
    {"from", ""}, 
    {"host", ""},
    {"if-match", ""}, 
    {"if-modified-since", ""}, 
    {"if-none-match", ""}, 
    {"if-range", ""},
    {"if-unmodified-since", ""}, 
    {"last-modified", ""}, 
    {"link", ""}, 
    {"location", ""},
    {"max-forwards", ""}, 
    {"proxy-authenticate", ""}, 
    {"proxy-authorization", ""}, 
    {"range", ""},
    {"referer", ""}, 
    {"refresh", ""}, 
    {"retry-after", ""}, 
    {"server", ""}, 
    {"set-cookie", ""},
    {"strict-transport-security", ""}, 
    {"transfer-encoding", ""}, 
    {"user-agent", ""}, 
    {"vary", ""},
    {"via", ""}, 
    {"www-authenticate", ""}
};

static bool hpack_get_header(HTTP2Session *session, uint32_t index, const char **name, const char **value);

static void hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value);

static uint32_t hpack_decode_int(const unsigned char **pos, const unsigned char *end, uint8_t prefix_mask);

static char* hpack_decode_string(const unsigned char **pos, const unsigned char *end);

static void process_literal_header_with_name(const char *name, const char *value, RequestHeader *req);

static void process_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req);

/* Public function */

bool http2_parser_frame_header(const unsigned char *buf, HTTP2FrameHeader *out) {
    if (!buf || !out) return false;
    out->length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
    out->type = buf[3];
    out->flags = buf[4];
    out->stream_id = ((buf[5] & 0x7F) << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8];
    return true;
}

bool http2_parser_parse_header(HTTP2Session *session, HTTP2Stream *stream, const unsigned char *payload, size_t len) {
    if (!payload || len == 0) return false;
    
    const unsigned char *pos = payload;
    const unsigned char *end = payload + len;
    RequestHeader *req = &stream->http1_compat;

    req->is_keep_alive = true; 
    req->vhost_context = NULL;
    req->path_info = NULL;
    memset(req->method, 0, sizeof(req->method));
    
    if (len > 5 && (payload[0] & 0x7F) == 0 && payload[1] == 0 && payload[2] == 0) {
        pos += 5;
    }

    pthread_mutex_lock(&session->hpack_lock);

    while (pos < end) {
        uint8_t b = *pos;
        
        if (b & 0x80) { 
            uint32_t index = hpack_decode_int(&pos, end, 0x7F);
            process_indexed_header(session, index, req);
        } 
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
                process_literal_header_with_name(name, value, req);
                hpack_dynamic_table_add(session, name, value);
            }
            if (name) free(name);
            if (value) free(value);
        }
        else if ((b & 0xE0) == 0x20) { 
            hpack_decode_int(&pos, end, 0x1F); 
        }
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
    
    if (req->uri) {
        char *qs = strchr(req->uri, '?');
        if (qs) {
            *qs = '\0';            
            req->query_string = qs + 1;
        }

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

        if (req->host) {
            VHostEntry *vh = (VHostEntry *)http_vhost_get_context(req->host);
            req->vhost_context = vh;

            if (req->uri[0] == '\0' || strcmp(req->uri, "/") == 0) {
                if (req->uri && req->uri != req->route_result) free(req->uri);
                snprintf(req->route_result, sizeof(req->route_result), "/index.html");
                req->uri = req->route_result; 
                req->path_info = NULL;
            }

            RouteTable *match = http_route_match(vh, req->uri);
            if (match) {
                char t_query[256], t_path[256];
                char *old_uri = req->uri; 
                
                http_route_apply_logic(match, old_uri, req->route_result, t_query, t_path);
                
                // --- FIX: Pastikan old_uri bukan pointer dari static_table sebelum di-free ---
                
                bool is_static_table_ptr = false;
                
                for(int i=0; i<=61; i++) {
                    if(old_uri == static_table[i].value) { is_static_table_ptr = true; break; }
                }

                bool is_dynamic_table_ptr = false;
                if (session) {
                    for (uint32_t i = 0; i < session->dyn_table.count; i++) {
                        if (old_uri == session->dyn_table.entries[i].name || 
                            old_uri == session->dyn_table.entries[i].value) {
                            is_dynamic_table_ptr = true;
                            break;
                        }
                    }
                }

                req->uri = req->route_result;
                // JANGAN free jika pointer milik static_table atau milik dynamic_table
                if (old_uri && old_uri != req->route_result && !is_static_table_ptr && !is_dynamic_table_ptr) {
                    free(old_uri);
                }

                req->backend_type = match->fcgi_type;

                if (t_query[0] != '\0') {
                    char *new_qs = strchr(req->uri, '?');
                    if (new_qs) {
                        *new_qs = '\0';
                        req->query_string = new_qs + 1;
                    } else {
                        strncpy(req->query_string_buffer, t_query, sizeof(req->query_string_buffer) - 1);
                        req->query_string_buffer[sizeof(req->query_string_buffer) - 1] = '\0';
                        req->query_string = req->query_string_buffer;
                    }
                }
            }
            else {
                req->backend_type = FCGI_PHP; 
            }
        }
        req->directory = req->uri;
    }

    req->is_valid = (req->method[0] != '\0' && req->uri != NULL);
    return req->is_valid;
}

void http2_parser_free_memory(HTTP2Stream *stream) {
    if (!stream) return;
    RequestHeader *req = &stream->http1_compat;

    #define IS_IN_ROUTE_RESULT(p) ((char*)(p) >= (char*)req->route_result && (char*)(p) < (char*)(req->route_result + sizeof(req->route_result)))

    // Bebaskan URI jika dialokasikan di heap (bukan menunjuk ke buffer statis internal route_result)
    if (req->uri && !IS_IN_ROUTE_RESULT(req->uri)) {
        free(req->uri);
    }
    req->uri = NULL;

    // Bebaskan Host jika dialokasikan di heap
    if (req->host && !IS_IN_ROUTE_RESULT(req->host)) {
        free(req->host);
    }
    req->host = NULL;

    // Sisa cleanup field request lainnya tetap sama
    if (req->content_type) { free(req->content_type); req->content_type = NULL; }
    if (req->cookie_data) { free(req->cookie_data); req->cookie_data = NULL; }

    if (req->parts) {
        http_multipart_free_parts(req->parts, req->parts_count);
        req->parts = NULL; 
        req->parts_count = 0;
    }

    if (req->body_data) { 
        free(req->body_data); 
        req->body_data = NULL; 
    }

    #undef IS_IN_ROUTE_RESULT
}

/* Private Function - Internal Helper */

bool hpack_get_header(HTTP2Session *session, uint32_t index, const char **name, const char **value) {
    if (index >= 1 && index <= 61) {
        *name = static_table[index].name;
        *value = static_table[index].value;
        return true;
    }

    if (session && session->dyn_table.count > 0) {
        uint32_t dyn_idx = index - 62;
        if (dyn_idx < session->dyn_table.count) {
            *name = session->dyn_table.entries[dyn_idx].name;
            *value = session->dyn_table.entries[dyn_idx].value;
            return true;
        }
    }
    return false;
}

void hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value)  {
    if (!session || !name || !value) return;
    if (session->dyn_table.entries == NULL) return;

    // --- FIX: Eviksi berbasis jumlah entri (Sesuai limit internal struct kamu) ---
    if (session->dyn_table.count >= 128) {
        int last_idx = session->dyn_table.count - 1;
        if (session->dyn_table.entries[last_idx].name) free(session->dyn_table.entries[last_idx].name);
        if (session->dyn_table.entries[last_idx].value) free(session->dyn_table.entries[last_idx].value);
        session->dyn_table.count = last_idx;
    }

    // Geser entri lama ke belakang
    for (int i = session->dyn_table.count; i > 0; i--) {
        session->dyn_table.entries[i] = session->dyn_table.entries[i-1];
    }

    // Masukkan entri baru di indeks 0
    session->dyn_table.entries[0].name = strdup(name);
    session->dyn_table.entries[0].value = strdup(value);
    session->dyn_table.count++;
}

uint32_t hpack_decode_int(const unsigned char **pos, const unsigned char *end, uint8_t prefix_mask) {
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
        if (!(b & 128)) {
            *pos = p;
            return res;
        }
        shift += 7;
        if (shift > 28) break; 
    }
    
    *pos = p;
    return res;
}

char* hpack_decode_string(const unsigned char **pos, const unsigned char *end) {
    if (*pos >= end) return NULL;
    
    uint8_t first_byte = **pos;
    bool is_huffman = (first_byte & 0x80) != 0;
    uint32_t len = hpack_decode_int(pos, end, 0x7F);

    // --- FIX: Majukan pointer ke 'end' jika terjadi error untuk mencegah Infinite Loop ---
    if (len > 10240 || *pos + len > end) {
        *pos = end; 
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

void process_literal_header_with_name(const char *name, const char *value, RequestHeader *req) {
    if (!name || !value) return;

    if (strcmp(name, "content-type") == 0) {
        if (req->content_type) free(req->content_type);
        req->content_type = strdup(value);
    } 
    else if (strcmp(name, "content-length") == 0) {
        req->content_length = strtol(value, NULL, 10);
    } 
    else if (strcmp(name, "cookie") == 0) {
        if (req->cookie_data == NULL) {
            req->cookie_data = strdup(value);
        } else {
            char *old = req->cookie_data;
            if (asprintf(&req->cookie_data, "%s; %s", old, value) != -1) {
                free(old);
            }
        }
    } 
    else if (strcmp(name, ":authority") == 0 || strcmp(name, "host") == 0) {
        if (req->host) free(req->host);
        req->host = strdup(value);
    } 
    else if (strcmp(name, ":method") == 0) {
        strncpy(req->method, value, sizeof(req->method) - 1);
        req->method[sizeof(req->method) - 1] = '\0';
    } 
    else if (strcmp(name, ":path") == 0) {
        if (req->uri) free(req->uri);
        req->uri = strdup(value);
    } 
    else if (strcmp(name, ":scheme") == 0) {
        req->is_tls = (strcmp(value, "https") == 0);
    }
    else if (strcmp(name, "x-forwarded-for") == 0 && config.trust_proxy) {
        char *val_dup = strdup(value);
        char *comma = strchr(val_dup, ',');
        if (comma) {
            size_t ip_len = comma - val_dup;
            if (ip_len < sizeof(req->client_ip)) {
                memcpy(req->client_ip, val_dup, ip_len);
                req->client_ip[ip_len] = '\0';
            }
        } else {
            strncpy(req->client_ip, val_dup, sizeof(req->client_ip) - 1);
            req->client_ip[sizeof(req->client_ip) - 1] = '\0';
        }
        free(val_dup);
    } 
    else if (strcmp(name, ":protocol") == 0) {
        if (strcmp(value, "websocket") == 0) {
            req->is_upgrade = true; 
        }
    }
}

void process_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req) {
    if (index == 0) return;
    const char *name = NULL;
    const char *value = NULL;

    if (hpack_get_header(session, index, &name, &value)) {
        process_literal_header_with_name(name, value, req);
    } 
}
