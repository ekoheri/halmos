#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "halmos_http2_parser.h"
#include "halmos_global.h"
#include "halmos_log.h"
#include "halmos_http_route.h"
#include "halmos_http_vhost.h"
#include "halmos_http_multipart.h"
#include "halmos_http2_stream.h"
#include "halmos_http2_hpack.h"
#include "halmos_http2_router.h"
#include "halmos_ws_system.h"
#include "halmos_sec_tls.h"
#include "halmos_sec_traffic.h"

#include "halmos_http2_frame.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

/* Helper http2_parser_handle_headers */
static bool parse_header(HTTP2Session *session, HTTP2Stream *stream, const unsigned char *payload, size_t len);
static size_t strip_headers_padding(HTTP2FrameHeader *head, const unsigned char **payload_ptr);
static bool check_rate_limit(HTTP2Session *session, HTTP2Stream *st, HTTP2FrameHeader *head); 

/* Helper http2_parser_handle_data */
static void handle_websocket_data_payload(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload);
static bool append_stream_body(HTTP2Session *session, HTTP2Stream *st, HTTP2FrameHeader *head, const unsigned char *payload);
static void handle_stream_end(HTTP2Session *session, HTTP2Stream *st);

/* Public Functions */

bool http2_parser_frame_header(const unsigned char *buf, HTTP2FrameHeader *out) {
    if (!buf || !out) return false;
    out->length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
    out->type = buf[3];
    out->flags = buf[4];
    out->stream_id = ((buf[5] & 0x7F) << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8];
    return true;
}

void http2_parser_handle_headers(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session || head->stream_id == 0) return;
 
    HTTP2Stream *st = http2_stream_get_or_create(session, head->stream_id);
    if (!st) return;
 
    const unsigned char *hpack_payload = payload;
    size_t hpack_len = strip_headers_padding(head, &hpack_payload);
 
    // Lempar hpack_payload ke HPACK Parser
    if (parse_header(session, st, hpack_payload, hpack_len) == true) {
        if (!check_rate_limit(session, st, head)) {
            return; 
        }
 
        // 1. JALUR WEBSOCKET UPGRADE VIA HEADERS
        if (st->http1_compat.is_upgrade == true) {
            http2_router_bridge(session, st);
            return;
        }
 
        // 2. JALUR REQUEST GET / TANPA BODY DATA (END_STREAM = 0x01)
        if (head->flags & 0x01) { 
            pthread_mutex_lock(&session->streams_lock);
            st->state = 2; // Half Closed Remote
            pthread_mutex_unlock(&session->streams_lock);
 
            http2_router_bridge(session, st);
        }
    } else {
        // HPACK Parse failed
    }
}

void http2_parser_handle_data(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session) return;
 
    HTTP2Stream *st = http2_stream_find(session, head->stream_id);
    if (!st) return;
    
    if (!payload || head->length == 0) return;
 
    // 1. Intersepsi Jalur WebSocket HTTP/2
    if (st->http1_compat.is_upgrade == true) {
        handle_websocket_data_payload(session, head, payload);
        return; 
    }
 
    // 2. Jalur Akumulasi Data HTTP/FastCGI Normal
    if (!append_stream_body(session, st, head, payload)) {
        return;
    }
 
    // Kirim window update untuk jalur data HTTP normal
    http2_frame_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
    http2_frame_send_window_update(session->fd, session->is_tls, 0, head->length);
 
    // 3. Cek apakah stream sudah berakhir (END_STREAM flag = 0x01)
    if (head->flags & 0x01) { 
        handle_stream_end(session, st);
    }
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

// Mendekompres binary header menjadi string yang dimengerti RequestHeader
bool parse_header(HTTP2Session *session, HTTP2Stream *stream, const unsigned char *payload, size_t len) {
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
            uint32_t index = http2_hpack_decode_int(&pos, end, 0x7F);
            status = http2_hpack_indexed_header(session, index, req);
        } 
        else if ((b & 0xC0) == 0x40) { 
            uint32_t index = http2_hpack_decode_int(&pos, end, 0x3F);
            char name_buf[HPACK_NAME_MAX] = {0};
            char val_buf[HPACK_VALUE_MAX] = {0};

            if (index == 0) {
                http2_hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf));
                //if (!hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf))) {
                //    status = 400; // HPACK / Compression Error
                //    break;
                //}
            } else {
                const char *s_name, *s_value;
                if (http2_hpack_get_header(session, index, &s_name, &s_value)) {
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
            http2_hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf));
            //if (!hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf))) {
            //    status = 400; // HPACK / Compression Error
            //    break;
            //}
            
            if (name_buf[0] != '\0' && val_buf[0] != '\0') {
                status = http2_hpack_literal_header_with_name(name_buf, val_buf, req);
                http2_hpack_dynamic_table_add(session, name_buf, val_buf);
            }
        }
        else if ((b & 0xE0) == 0x20) { 
            http2_hpack_decode_int(&pos, end, 0x1F); 
        }
        else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
            uint32_t index = http2_hpack_decode_int(&pos, end, 0x0F);
            char name_buf[HPACK_NAME_MAX] = {0};
            char val_buf[HPACK_VALUE_MAX] = {0};

            if (index == 0) {
                http2_hpack_decode_string_buf(&pos, end, name_buf, sizeof(name_buf));
            } else {
                const char *s_name, *s_value;
                if (http2_hpack_get_header(session, index, &s_name, &s_value)) {
                    snprintf(name_buf, sizeof(name_buf), "%s", s_name);
                }
            }
            http2_hpack_decode_string_buf(&pos, end, val_buf, sizeof(val_buf));
            
            if (name_buf[0] != '\0' && val_buf[0] != '\0') {
                status = http2_hpack_literal_header_with_name(name_buf, val_buf, req);
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
    //if (req->is_valid) {
    //    const char *ip_to_log = (strlen(req->client_ip) > 0) ? req->client_ip : "unknown_ip";
    //    write_log("[HTTP2] %s %s (Client IP: %s)", req->method, req->uri, ip_to_log);
    //}
    return req->is_valid;
}


// Membersihkan padding & priority pada payload header
size_t strip_headers_padding(HTTP2FrameHeader *head, const unsigned char **payload_ptr) {
    const unsigned char *hpack_payload = *payload_ptr;
    size_t hpack_len = head->length;
    uint8_t pad_len = 0;
 
    if (head->flags & 0x08) { // PADDED Flag
        if (hpack_len > 0) {
            pad_len = hpack_payload[0];
            hpack_payload += 1;
            hpack_len -= 1;
        }
    }
 
    if (head->flags & 0x20) { // PRIORITY Flag
        if (hpack_len >= 5) {
            hpack_payload += 5; 
            hpack_len -= 5;
        }
    }
 
    if (hpack_len > pad_len) {
        hpack_len -= pad_len; 
    } else {
        hpack_len = 0;
    }
    
    *payload_ptr = hpack_payload;
    return hpack_len;
}

// Memeriksa rate limit trafik klien
bool check_rate_limit(HTTP2Session *session, HTTP2Stream *st, HTTP2FrameHeader *head) {
    if (config.rate_limit_enabled == true) {
        int limit = (config.max_requests_per_sec > 0) ? config.max_requests_per_sec : 50;
        if (!sec_traffic_is_request_allowed(st->http1_compat.client_ip, limit)) {
            write_log("[H2-SECURITY] Rate limit exceeded for IP: %s. Stream %u rejected.", 
                      st->http1_compat.client_ip, head->stream_id);
            
            unsigned char error_payload[4] = {0x00, 0x00, 0x00, 0x07}; 
            http2_frame_send(session->fd, session->is_tls, 0x03, 0x00, head->stream_id, error_payload, 4);
            return false; 
        }
    }
    return true;
}

// Menangani pembongkaran frame WebSocket di dalam HTTP/2 DATA frame
void handle_websocket_data_payload(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (head->length < 2) return; 

    uint8_t opcode = payload[0] & 0x0F;
    bool masked = (payload[1] & 0x80) != 0;
    uint64_t payload_len = payload[1] & 0x7F;
    size_t header_offset = 2; 

    if (payload_len == 126) {
        if (head->length < 4) return;
        uint16_t ext_len;
        memcpy(&ext_len, payload + header_offset, 2);
        payload_len = ntohs(ext_len);
        header_offset += 2;
    } else if (payload_len == 127) {
        if (head->length < 10) return;
        uint64_t ext_len;
        memcpy(&ext_len, payload + header_offset, 8);
        payload_len = be64toh(ext_len);
        header_offset += 8;
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (head->length < header_offset + 4) return;
        memcpy(mask, payload + header_offset, 4);
        header_offset += 4;
    }

    if (header_offset + payload_len > head->length || payload_len == __UINT64_MAX__) {
        return;
    }

    unsigned char *clear_payload = malloc(payload_len + 1);
    if (!clear_payload) return;

    memcpy(clear_payload, payload + header_offset, payload_len);
    clear_payload[payload_len] = '\0';

    if (masked) {
        for (size_t i = 0; i < payload_len; i++) {
            clear_payload[i] ^= mask[i % 4];
        }
    }

    if (opcode == 0x01) { // WS_OP_TEXT
        ws_system_on_message(session->fd, head->stream_id, (unsigned char *)clear_payload, payload_len);
    } else if (opcode == 0x08) { // WS_OP_CLOSE
        // Handle close stream jika diperlukan
    }

    free(clear_payload);

    http2_frame_send_window_update(session->fd, session->is_tls, head->stream_id, head->length);
    http2_frame_send_window_update(session->fd, session->is_tls, 0, head->length);
}

// Mengakumulasi payload data HTTP normal ke dalam buffer stream
bool append_stream_body(HTTP2Session *session, HTTP2Stream *st, HTTP2FrameHeader *head, const unsigned char *payload) {
    pthread_mutex_lock(&session->streams_lock);

    RequestHeader *req = &st->http1_compat;
    size_t new_size = req->body_length + head->length;
    
    if (new_size < req->body_length) {
        pthread_mutex_unlock(&session->streams_lock);
        return false; // Integer overflow guard
    }

    unsigned char *temp_body = realloc(req->body_data, new_size + 1);
    if (!temp_body) {
        pthread_mutex_unlock(&session->streams_lock); 
        write_log_error("[H2-ERROR] Realloc failed for Stream ID %d", head->stream_id);
        return false; 
    }
    req->body_data = temp_body;

    memcpy((char*)req->body_data + req->body_length, payload, head->length);
    req->body_length = new_size;
    ((char*)req->body_data)[req->body_length] = '\0';

    pthread_mutex_unlock(&session->streams_lock);
    return true;
}

// Menangani penyelesaian stream saat flag END_STREAM diterima
void handle_stream_end(HTTP2Session *session, HTTP2Stream *st) {
    pthread_mutex_lock(&session->streams_lock);
    st->http1_compat.content_length = (int)st->http1_compat.body_length; 
    pthread_mutex_unlock(&session->streams_lock);

    // Menyeberang ke Backend / Routing Bridge
    http2_router_bridge(session, st);

    pthread_mutex_lock(&session->streams_lock);
    st->state = 4; // Closed state
    pthread_mutex_unlock(&session->streams_lock);
}
