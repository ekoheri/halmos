#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

static const HPACKStaticEntry static_table[] = {
    {NULL, NULL}, 
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

static bool hpack_get_header(HTTP2Session *session, uint32_t index, const char **name, const char **value);
static void hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value);
static uint32_t hpack_decode_int(const unsigned char **pos, const unsigned char *end, uint8_t prefix_mask);
static bool hpack_decode_string_buf(const unsigned char **pos, const unsigned char *end, char *out_buf, size_t out_max);
static int process_literal_header_with_name(const char *name, const char *value, RequestHeader *req);
static int process_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req);

/* Public Functions */

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
    req->uri = NULL;
    req->host = NULL;
    req->content_type = NULL;
    req->cookie_data = NULL;
    req->error_code = 0;
    
    memset(req->method, 0, sizeof(req->method));
    memset(req->h2_uri_buf, 0, sizeof(req->h2_uri_buf));
    memset(req->h2_host_buf, 0, sizeof(req->h2_host_buf));
    memset(req->h2_content_type_buf, 0, sizeof(req->h2_content_type_buf));
    memset(req->h2_cookie_buf, 0, sizeof(req->h2_cookie_buf));

    pthread_mutex_lock(&session->hpack_lock);

    while (pos < end) {
        uint8_t b = *pos;
        int status = 0;
        
        if (b & 0x80) { 
            uint32_t index = hpack_decode_int(&pos, end, 0x7F);
            status = process_indexed_header(session, index, req);
        } 
        else if ((b & 0xC0) == 0x40) { 
            uint32_t index = hpack_decode_int(&pos, end, 0x3F);
            char name_buf[HPACK_NAME_MAX] = {0};
            char val_buf[HPACK_VALUE_MAX] = {0};

            if (index == 0) {
                hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf));
                //if (!hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf))) {
                //    status = 400; // HPACK / Compression Error
                //    break;
                //}
            } else {
                const char *s_name, *s_value;
                if (hpack_get_header(session, index, &s_name, &s_value)) {
                    snprintf(name_buf, sizeof(name_buf), "%s", s_name);
                }

                //const char *s_name, *s_value;
                //if (hpack_get_header(session, index, &s_name, &s_value)) {
                //    snprintf(name_buf, sizeof(name_buf), "%s", s_name);
                //} else {
                //    status = 400; // Invalid index
                //    break;
                //}
            }
            hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf));
            //if (!hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf))) {
            //    status = 400; // HPACK / Compression Error
            //    break;
            //}
            
            if (name_buf[0] != '\0' && val_buf[0] != '\0') {
                status = process_literal_header_with_name(name_buf, val_buf, req);
                hpack_dynamic_table_add(session, name_buf, val_buf);
            }
        }
        else if ((b & 0xE0) == 0x20) { 
            hpack_decode_int(&pos, end, 0x1F); 
        }
        else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
            uint32_t index = hpack_decode_int(&pos, end, 0x0F);
            char name_buf[HPACK_NAME_MAX] = {0};
            char val_buf[HPACK_VALUE_MAX] = {0};

            if (index == 0) {
                hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf));
            } else {
                const char *s_name, *s_value;
                if (hpack_get_header(session, index, &s_name, &s_value)) {
                    snprintf(name_buf, sizeof(name_buf), "%s", s_name);
                }
            }
            hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf));
            
            if (name_buf[0] != '\0' && val_buf[0] != '\0') {
                status = process_literal_header_with_name(name_buf, val_buf, req);
            }
        }
        else {
            pos++;
        }

        if (status != 0) {
            req->error_code = status;
            pthread_mutex_unlock(&session->hpack_lock);
            req->is_valid = false;
            return false;
        }
    }

    pthread_mutex_unlock(&session->hpack_lock);

    /* --- LOGIKA ROUTING ZERO-ALLOCATION --- */
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
                snprintf(req->h2_uri_buf, sizeof(req->h2_uri_buf), "/index.html");
                req->uri = req->h2_uri_buf;
                req->path_info = NULL;
            }

            RouteTable *match = http_route_match(vh, req->uri);
            if (match) {
                char t_query[256] = {0}, t_path[256] = {0};
                char route_buf[HTTP2_URI_MAX] = {0};
                
                http_route_apply_logic(match, req->uri, route_buf, t_query, t_path);

                if (strlen(route_buf) >= sizeof(req->h2_uri_buf)) {
                    req->error_code = 414; // URI Too Long
                    req->is_valid = false;
                    return false;
                }

                snprintf(req->h2_uri_buf, sizeof(req->h2_uri_buf), "%s", route_buf);
                req->uri = req->h2_uri_buf;

                req->backend_type = match->fcgi_type;

                if (t_query[0] != '\0') {
                    char *new_qs = strchr(req->uri, '?');
                    if (new_qs) {
                        *new_qs = '\0';
                        req->query_string = new_qs + 1;
                    } else {
                        snprintf(req->query_string_buffer, sizeof(req->query_string_buffer), "%s", t_query);
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
    // --- LOGGING HTTP/2 REQUEST ---
    if (req->is_valid) {
        const char *ip_to_log = (strlen(req->client_ip) > 0) ? req->client_ip : "unknown_ip";
        write_log("[HTTP2] %s %s (Client IP: %s)", req->method, req->uri, ip_to_log);
    }
    return req->is_valid;
}

void http2_parser_free_memory(HTTP2Stream *stream) {
    if (!stream) return;
    RequestHeader *req = &stream->http1_compat;

    req->uri = NULL;
    req->host = NULL;
    req->content_type = NULL;
    req->cookie_data = NULL;

    if (req->parts) {
        http_multipart_free_parts(req->parts, req->parts_count);
        req->parts = NULL; 
        req->parts_count = 0;
    }

    if (req->body_data) { 
        free(req->body_data); 
        req->body_data = NULL; 
    }
}

/* Helper Functions Internal */

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

void hpack_dynamic_table_add(HTTP2Session *session, const char *name, const char *value) {
    if (!session || !name || !value) return;
    if (session->dyn_table.entries == NULL) return;

    if (session->dyn_table.count >= 128) {
        session->dyn_table.count = 127;
    }

    for (int i = session->dyn_table.count; i > 0; i--) {
        session->dyn_table.entries[i] = session->dyn_table.entries[i-1];
    }

    snprintf(session->dyn_table.entries[0].name, sizeof(session->dyn_table.entries[0].name), "%s", name);
    snprintf(session->dyn_table.entries[0].value, sizeof(session->dyn_table.entries[0].value), "%s", value);

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

static bool hpack_decode_string_buf(const unsigned char **pos, const unsigned char *end, char *out_buf, size_t out_max) {
    if (*pos >= end || !out_buf || out_max == 0) return false;

    uint8_t first_byte = **pos;
    bool is_huffman = (first_byte & 0x80) != 0;
    uint32_t len = hpack_decode_int(pos, end, 0x7F);

    if (len > 10240 || *pos + len > end) {
        *pos = end;
        return false;
    }

    if (is_huffman) {
        // Zero-allocation: Langsung dekode ke out_buf yang dialokasikan di stack oleh caller
        if (!http2_huffman_decode(*pos, len, out_buf, out_max)) {
            // Jika gagal decode, pastikan buffer bersih tapi TETAP majukan *pos agar stream tidak macet
            out_buf[0] = '\0';
        }
    } else {
        size_t copy_len = (len < out_max - 1) ? len : (out_max - 1);
        memcpy(out_buf, *pos, copy_len);
        out_buf[copy_len] = '\0';
    }

    *pos += len; // Wajib dipanggil agar *pos selalu maju & mutex hpack_lock dilepas dengan aman
    return true;
}

static int process_literal_header_with_name(const char *name, const char *value, RequestHeader *req) {
    if (!name || !value) return 0;
    size_t val_len = strlen(value);

    if (strcmp(name, ":path") == 0) {
        if (val_len >= sizeof(req->h2_uri_buf)) {
            return 414; // URI Too Long
        }
        snprintf(req->h2_uri_buf, sizeof(req->h2_uri_buf), "%s", value);
        req->uri = req->h2_uri_buf;
    } 
    else if (strcmp(name, ":authority") == 0 || strcmp(name, "host") == 0) {
        if (val_len >= sizeof(req->h2_host_buf)) {
            return 431; // Request Header Fields Too Large
        }
        snprintf(req->h2_host_buf, sizeof(req->h2_host_buf), "%s", value);
        req->host = req->h2_host_buf;
    } 
    else if (strcmp(name, "content-type") == 0) {
        if (val_len >= sizeof(req->h2_content_type_buf)) {
            return 431; 
        }
        snprintf(req->h2_content_type_buf, sizeof(req->h2_content_type_buf), "%s", value);
        req->content_type = req->h2_content_type_buf;
    } 
    else if (strcmp(name, "cookie") == 0) {
        size_t current_len = strlen(req->h2_cookie_buf);
        
        if (current_len == 0) {
            if (val_len >= sizeof(req->h2_cookie_buf)) {
                return 431; // Request Header Fields Too Large
            }
            memcpy(req->h2_cookie_buf, value, val_len + 1);
        } else {
            // Cek apakah buffer cukup menampung "; " + value + null terminator
            if (current_len + 2 + val_len >= sizeof(req->h2_cookie_buf)) {
                return 431; 
            }
            
            // Menggunakan memcpy/strcat manual menghilangkan warning snprintf truncation
            char *ptr = req->h2_cookie_buf + current_len;
            ptr[0] = ';';
            ptr[1] = ' ';
            memcpy(ptr + 2, value, val_len + 1); // +1 untuk menyalin null-terminator '\0'
        }
        req->cookie_data = req->h2_cookie_buf;
    } 
    else if (strcmp(name, "content-length") == 0) {
        req->content_length = strtol(value, NULL, 10);
    } 
    else if (strcmp(name, ":method") == 0) {
        if (val_len >= sizeof(req->method)) {
            return 431;
        }
        snprintf(req->method, sizeof(req->method), "%s", value);
    } 
    else if (strcmp(name, ":scheme") == 0) {
        req->is_tls = (strcmp(value, "https") == 0);
    }
    else if (strcmp(name, "x-forwarded-for") == 0 && config.trust_proxy) {
        const char *comma = strchr(value, ',');
        if (comma) {
            size_t ip_len = comma - value;
            if (ip_len < sizeof(req->client_ip)) {
                memcpy(req->client_ip, value, ip_len);
                req->client_ip[ip_len] = '\0';
            }
        } else {
            if (val_len >= sizeof(req->client_ip)) {
                return 431;
            }
            snprintf(req->client_ip, sizeof(req->client_ip), "%s", value);
        }
    } 
    else if (strcmp(name, ":protocol") == 0) {
        if (strcmp(value, "websocket") == 0) {
            req->is_upgrade = true; 
        }
    }

    return 0;
}

static int process_indexed_header(HTTP2Session *session, uint32_t index, RequestHeader *req) {
    if (index == 0) return 0;
    const char *name = NULL;
    const char *value = NULL;

    if (hpack_get_header(session, index, &name, &value)) {
        return process_literal_header_with_name(name, value, req);
    } 
    return 0;
}