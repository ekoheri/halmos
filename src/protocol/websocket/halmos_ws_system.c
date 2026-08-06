#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_ws_system.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
#include "halmos_sec_tls.h"
#include "halmos_http1_header.h"        
#include "halmos_core_event_loop.h"     
#include "halmos_ws_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdbool.h>                     
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <arpa/inet.h>   
#include <endian.h>      

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define MAX_WS_PAYLOAD (10 * 1024 * 1024)
#ifndef MAX_FDS
#define MAX_FDS 65536
#endif

static bool ws_fd_map[MAX_FDS]; 

/* State machine receiver per-FD menggunakan ws_state_t yang didefinisikan di .h */
typedef struct {
    ws_state_t state;
    
    // Header Buffers
    uint8_t header[2];
    size_t header_bytes_read;
    
    uint8_t ext_len_buf[8];
    size_t ext_len_expected;
    size_t ext_len_bytes_read;
    
    uint8_t mask[4];
    size_t mask_bytes_read;
    
    // Frame Metadata
    bool fin;
    int opcode;
    bool masked;
    uint64_t payload_len;
    
    // Payload Accumulator
    uint8_t *payload;
    size_t payload_bytes_read;
} ws_recv_state_t;

// Array global penampung state receiver per FD
static ws_recv_state_t *g_recv_states[MAX_FDS] = {NULL};

/* Dynamic Allocation State Helper */
static ws_recv_state_t* ws_get_or_create_recv_state(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return NULL;
    if (!g_recv_states[fd]) {
        g_recv_states[fd] = calloc(1, sizeof(ws_recv_state_t));
        g_recv_states[fd]->state = WS_STATE_HEADER;
    }
    return g_recv_states[fd];
}

static void ws_reset_recv_state(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_recv_states[fd]) {
        if (g_recv_states[fd]->payload) {
            free(g_recv_states[fd]->payload);
        }
        memset(g_recv_states[fd], 0, sizeof(ws_recv_state_t));
        g_recv_states[fd]->state = WS_STATE_HEADER;
    }
}

static void ws_free_recv_state(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_recv_states[fd]) {
        if (g_recv_states[fd]->payload) {
            free(g_recv_states[fd]->payload);
        }
        free(g_recv_states[fd]);
        g_recv_states[fd] = NULL;
    }
}

/* Forward Declarations Helper & Utility */
static char* ws_base64_encode(const unsigned char *input, int length);
static char* ws_create_accept_key(const char *client_key);
static ssize_t ws_low_level_recv(int fd, void *buf, size_t len);
static ssize_t ws_low_level_send(int fd, const void *buf, size_t len);
static void ws_system_send_pong(int sock_client);
static void* ws_system_maintenance_run(void *arg);
static void ws_system_start_maintenance(void);

static inline ws_action_ipc_t get_action_code(const char *s) {
    if (!s) return ACT_UNKNOWN;
    if (strcmp(s, "AUTH") == 0)      return ACT_AUTH;
    if (strcmp(s, "PRIVATE") == 0)   return ACT_PRIVATE;
    if (strcmp(s, "BROADCAST") == 0) return ACT_BROADCAST;
    if (strcmp(s, "GROUP") == 0)     return ACT_GROUP;
    if (strcmp(s, "PUB") == 0)       return ACT_PUB;
    if (strcmp(s, "SUB") == 0)       return ACT_SUB;
    if (strcmp(s, "REQ") == 0)       return ACT_REQ;
    return ACT_UNKNOWN;
}

/* ===================================================================
 * 1. SYSTEM INIT & LIFECYCLE MANAGEMENT
 * =================================================================== */

void halmos_ws_system_init(void) {
    ws_registry_init();
    memset(g_recv_states, 0, sizeof(g_recv_states));
    ws_system_start_maintenance();
    write_log("[WS] Infrastructure Ready with State Machine Receiver.");
}

void ws_system_destroy(void) {
    for (int i = 0; i < MAX_FDS; i++) {
        ws_free_recv_state(i);
    }
    ws_registry_destroy();
    write_log("[WS] System resources & receiver states destroyed.");
}

void ws_system_cleanup_fd(int fd) {
    if (halmos_is_websocket_fd(fd)) {
        ws_free_recv_state(fd);
        ws_registry_remove(fd);
        halmos_set_websocket_fd(fd, false);
        write_log("[WS] Cleanup complete for FD %d", fd);
    }
}

bool halmos_is_websocket_fd(int fd) {
    if (fd >= 0 && fd < MAX_FDS) return ws_fd_map[fd];
    return false;
}

void halmos_set_websocket_fd(int fd, bool status) {
    if (fd >= 0 && fd < MAX_FDS) ws_fd_map[fd] = status;
}

static void ws_system_start_maintenance(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, ws_system_maintenance_run, NULL) == 0) {
        pthread_detach(tid);
    } else {
        write_log_error("[WS-SYSTEM] Failed to start maintenance thread!");
    }
}

/* ===================================================================
 * 2. HTTP/1.1 HANDSHAKE
 * =================================================================== */

bool ws_is_upgrade_request(RequestHeader *req) {
    if (strcasecmp(req->method, "GET") != 0) return false;
    if (!req->is_upgrade) return false;
    if (req->ws.key == NULL || req->ws.key[0] == '\0') return false;
    return true;
}

int ws_upgrade_handshake(int sock_client, RequestHeader *req) {
    if (!req->ws.key) return -1;

    char *accept_key = ws_create_accept_key(req->ws.key);
    if (!accept_key) return -1;

    char response[512];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Server: Halmos-Savage/2.1\r\n\r\n",
        accept_key);

    SSL *ssl = ssl_get_for_fd(sock_client);
    ssize_t sent = 0;

    if (ssl) {
        int r = SSL_write(ssl, response, len);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                free(accept_key);
                return -2; // Signals EAGAIN
            }
            free(accept_key);
            return -1;
        }
        sent = r;
    } else {
        sent = send(sock_client, response, len, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                free(accept_key);
                return -2;
            }
            free(accept_key);
            return -1;
        }
    }

    free(accept_key);

    int slot = ws_registry_add(sock_client, ssl);
    if (slot != -1) {
        write_log("[WS-REGISTRY] FD %d registered in slot %d", sock_client, slot);
        ws_registry_broadcast("{\"event\": \"new_user\", \"msg\": \"Seseorang baru saja bergabung!\"}");
    } else {
        write_log("[WS-REGISTRY] ERROR: Registry Full for FD %d", sock_client);
    }

    halmos_set_websocket_fd(sock_client, true);
    write_log("[WS] Handshake OK on FD %d", sock_client);
    return 0;
}

/* ===================================================================
 * 3. STATE MACHINE RECEIVER ENGINE (NON-BLOCKING)
 * =================================================================== */

ws_recv_status_t halmos_ws_recv_frame(int fd, int *opcode, unsigned char **out_payload, size_t *out_len) {
    ws_recv_state_t *st = ws_get_or_create_recv_state(fd);
    if (!st) return WS_RECV_FATAL;

    while (st->state != WS_STATE_COMPLETE) {
        switch (st->state) {
            
            /* STEP 1: READ INITIAL 2-BYTE HEADER */
            case WS_STATE_HEADER: {
                size_t needed = 2 - st->header_bytes_read;
                ssize_t n = ws_low_level_recv(fd, st->header + st->header_bytes_read, needed);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return WS_RECV_AGAIN;
                    return WS_RECV_FATAL;
                }
                st->header_bytes_read += (size_t)n;
                if (st->header_bytes_read < 2) return WS_RECV_AGAIN;

                st->fin = (st->header[0] & 0x80) != 0;
                st->opcode = st->header[0] & 0x0F;
                st->masked = (st->header[1] & 0x80) != 0;
                st->payload_len = st->header[1] & 0x7F;

                /* RFC Validation 1: Fragmentation Check */
                if (!st->fin) {
                    write_log_error("[WS-RFC6455] FD %d: Fragmentation intentionally unsupported (FIN=0). Dropping.", fd);
                    return WS_RECV_FATAL;
                }

                /* RFC Validation 2: Control Frame Payload Limits */
                bool is_control_frame = (st->opcode >= 0x08 && st->opcode <= 0x0A);
                if (is_control_frame && st->payload_len > 125) {
                    write_log_error("[WS-RFC6455] FD %d: Control frame exceeds 125 bytes limit (%zu bytes).", fd, st->payload_len);
                    return WS_RECV_FATAL;
                }

                /* RFC Validation 3: Client-to-Server Masking Enforcer */
                if (!st->masked) {
                    write_log_error("[WS-RFC6455] FD %d: Client-to-server frame unmasked. Violation!", fd);
                    return WS_RECV_FATAL;
                }

                if (st->payload_len == 126) {
                    st->ext_len_expected = 2;
                    st->state = WS_STATE_EXT_LEN;
                } else if (st->payload_len == 127) {
                    st->ext_len_expected = 8;
                    st->state = WS_STATE_EXT_LEN;
                } else {
                    st->state = WS_STATE_MASK;
                }
                break;
            }

            /* STEP 2: READ EXTENDED PAYLOAD LENGTH */
            case WS_STATE_EXT_LEN: {
                size_t needed = st->ext_len_expected - st->ext_len_bytes_read;
                ssize_t n = ws_low_level_recv(fd, st->ext_len_buf + st->ext_len_bytes_read, needed);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return WS_RECV_AGAIN;
                    return WS_RECV_FATAL;
                }
                st->ext_len_bytes_read += (size_t)n;
                if (st->ext_len_bytes_read < st->ext_len_expected) return WS_RECV_AGAIN;

                if (st->ext_len_expected == 2) {
                    uint16_t net16;
                    memcpy(&net16, st->ext_len_buf, 2);
                    st->payload_len = ntohs(net16);
                } else {
                    uint64_t net64;
                    memcpy(&net64, st->ext_len_buf, 8);
                    st->payload_len = be64toh(net64);
                }

                if (st->payload_len > MAX_WS_PAYLOAD) {
                    write_log_error("[SECURITY] FD %d payload size limit exceeded (%zu bytes).", fd, st->payload_len);
                    return WS_RECV_FATAL;
                }

                st->state = WS_STATE_MASK;
                break;
            }

            /* STEP 3: READ 4-BYTE MASKING KEY */
            case WS_STATE_MASK: {
                size_t needed = 4 - st->mask_bytes_read;
                ssize_t n = ws_low_level_recv(fd, st->mask + st->mask_bytes_read, needed);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return WS_RECV_AGAIN;
                    return WS_RECV_FATAL;
                }
                st->mask_bytes_read += (size_t)n;
                if (st->mask_bytes_read < 4) return WS_RECV_AGAIN;

                if (st->payload_len > 0) {
                    st->payload = malloc(st->payload_len + 1);
                    if (!st->payload) return WS_RECV_FATAL;
                    st->state = WS_STATE_PAYLOAD;
                } else {
                    st->state = WS_STATE_COMPLETE;
                }
                break;
            }

            /* STEP 4: READ PAYLOAD ACCUMULATIVELY */
            case WS_STATE_PAYLOAD: {
                size_t needed = st->payload_len - st->payload_bytes_read;
                ssize_t n = ws_low_level_recv(fd, st->payload + st->payload_bytes_read, needed);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return WS_RECV_AGAIN;
                    return WS_RECV_FATAL;
                }
                st->payload_bytes_read += (size_t)n;
                if (st->payload_bytes_read < st->payload_len) {
                    return WS_RECV_AGAIN;
                }

                st->state = WS_STATE_COMPLETE;
                break;
            }

            case WS_STATE_COMPLETE:
                break;
        }
    }

    // Unmask Payload
    if (st->payload && st->payload_len > 0) {
        st->payload[st->payload_len] = '\0';
        for (size_t i = 0; i < st->payload_len; i++) {
            st->payload[i] ^= st->mask[i % 4];
        }
    }

    *opcode = st->opcode;
    *out_payload = st->payload;
    *out_len = st->payload_len;

    st->payload = NULL; 
    ws_reset_recv_state(fd);

    return WS_RECV_OK;
}
/* ===================================================================
 * 4. DISPATCHER & EVENT HANDLER
 * =================================================================== */

int ws_system_dispatch(int sock_client) {
    int opcode;
    unsigned char *payload = NULL;
    size_t payload_len = 0;

    int res = halmos_ws_recv_frame(sock_client, &opcode, &payload, &payload_len);

    if (res == WS_RECV_AGAIN) return 1; 
    if (res == WS_RECV_FATAL) {
        write_log("[WS] Connection disconnect / fatal error on FD %d", sock_client);
        return 0; 
    }

    switch (opcode) {
        case WS_OP_TEXT:
            if (payload) {
                ws_system_on_message(sock_client, 0, payload, payload_len);
            }
            break;

        case WS_OP_BIN:
            write_log("[WS] Received binary frame (%zu bytes) on FD %d", payload_len, sock_client);
            break;

        case WS_OP_PING:
            ws_system_send_pong(sock_client); 
            break;

        case WS_OP_PONG:
            ws_registry_update_activity(sock_client);
            break;

        case WS_OP_CLOSE: {
            uint16_t close_code = 1000;
            if (payload_len >= 2) {
                uint16_t raw_code;
                memcpy(&raw_code, payload, 2);
                close_code = ntohs(raw_code);
            }
            write_log("[WS-CLOSE] FD %d client requested close (Code: %u)", sock_client, close_code);
            if (payload) free(payload);
            return 0;
        }

        default:
            break;
    }

    if (payload) free(payload);
    return 1;
}

void ws_system_on_message(int sock_client, uint32_t stream_id, unsigned char *data, size_t len) {
    if (len == 0 || data == NULL) return;

    struct json_tokener *tok = json_tokener_new();
    struct json_object *parsed_json = json_tokener_parse_ex(tok, (const char *)data, len);

    if (parsed_json == NULL) {
        write_log_error("[WS-JSON] Malformed JSON on FD %d (Stream %u)", sock_client, stream_id);
        json_tokener_free(tok);
        return;
    }

    struct json_object *header_obj = NULL;
    if (json_object_object_get_ex(parsed_json, K_HEADER, &header_obj)) {
        struct json_object *action_obj = NULL;
        struct json_object *dst_obj = NULL;
        struct json_object *app_obj = NULL;

        json_object_object_get_ex(header_obj, K_ACTION, &action_obj);
        json_object_object_get_ex(header_obj, K_DST, &dst_obj);
        json_object_object_get_ex(header_obj, K_APP, &app_obj);

        if (action_obj && dst_obj) {
            const char *action = json_object_get_string(action_obj);
            const char *target = json_object_get_string(dst_obj);
            const char *app_id = app_obj ? json_object_get_string(app_obj) : "GLOBAL";

            ws_action_ipc_t action_code = get_action_code(action);

            switch (action_code) {
                case ACT_AUTH: {
                    struct json_object *pay_obj = NULL;
                    json_object_object_get_ex(parsed_json, K_PAYLOAD, &pay_obj);
                    if (pay_obj) {
                        const char *user_id = json_object_get_string(pay_obj);
                        ws_registry_set_user_id(sock_client, user_id);
                        write_log("[WS-AUTH] FD %d (Stream %u) => %s", sock_client, stream_id, user_id);
                    }
                    break;
                }
                case ACT_PRIVATE: {
                    const char *from_user = ws_registry_get_user_id(sock_client);
                    int target_fd = -1;
                    uint64_t target_session = 0;
                    SSL *target_ssl = NULL;

                    if (ws_registry_get_session_info(target, &target_fd, &target_session, &target_ssl)) {
                        bool is_target_h2 = false;
                        uint32_t target_stream_id = 0;
                        ws_registry_get_h2_status(target_fd, &is_target_h2, &target_stream_id);

                        ws_outgoing_frame_t *pending = NULL;
                        ws_send_status_t send_st;

                        if (is_target_h2) {
                            send_st = ws_system_send_text_h2(target_fd, target_stream_id, (const char *)data, &pending);
                        } else {
                            send_st = ws_system_send_text(target_fd, target_ssl, (const char *)data, len, &pending);
                        }
                        
                        if (send_st == WS_SEND_RETRY && pending != NULL) {
                            write_log("[WS-QUEUE] Partial send on FD %d. Frame preserved for Outbound Queue.", target_fd);
                            // Push ke outbound queue caller / epoll out context jika tersedia
                        }

                        write_log("[WS-PRIVATE] %s -> %s (Status: %d)", from_user ? from_user : "Anon", target, send_st);
                    }
                    break;
                }
                case ACT_BROADCAST:
                    ws_registry_broadcast((const char *)data);
                    break;
                case ACT_PUB:
                    ws_registry_publish("GLOBAL", target, (const char *)data);
                    break;
                case ACT_SUB:
                    ws_registry_add_to_topic(sock_client, app_id, target);
                    break;
                default:
                    break;
            }
        }
    }

    json_object_put(parsed_json);
    json_tokener_free(tok);
}

void ws_system_internal_dispatch(const char *json_raw) {
    if (!json_raw) return;

    struct json_tokener *tok = json_tokener_new();
    struct json_object *parsed_json = json_tokener_parse_ex(tok, json_raw, strlen(json_raw));
    if (!parsed_json) {
        write_log_error("[WS-IPC] Malformed Internal JSON!");
        json_tokener_free(tok);
        return;
    }

    struct json_object *header_obj = NULL;
    if (json_object_object_get_ex(parsed_json, K_HEADER, &header_obj)) {
        struct json_object *action_obj = NULL;
        json_object_object_get_ex(header_obj, K_ACTION, &action_obj);
        const char *action_val = action_obj ? json_object_get_string(action_obj) : "";

        if (strcmp(action_val, "SET_IDENTITY") == 0) {
            struct json_object *fd_obj = NULL;
            struct json_object *uid_obj = NULL;
            json_object_object_get_ex(header_obj, "target_fd", &fd_obj);
            json_object_object_get_ex(header_obj, "user_id", &uid_obj);

            if (fd_obj && uid_obj) {
                int target_fd = json_object_get_int(fd_obj);
                const char *user_id = json_object_get_string(uid_obj);
                ws_registry_set_user_id(target_fd, user_id);
                write_log("[WS-IPC] Identity Linked: FD %d => User %s", target_fd, user_id);
            }
        } else {
            struct json_object *dst_obj = NULL;
            struct json_object *src_obj = NULL;
            json_object_object_get_ex(header_obj, K_DST, &dst_obj);
            json_object_object_get_ex(header_obj, K_SRC, &src_obj);

            const char *target = dst_obj ? json_object_get_string(dst_obj) : NULL;
            const char *source = src_obj ? json_object_get_string(src_obj) : NULL;

            if (source && strncmp(source, INTERNAL_PREFIX, strlen(INTERNAL_PREFIX)) == 0 && target) {
                if (strcmp(target, "BROADCAST") == 0) {
                    ws_registry_broadcast(json_raw);
                } else {
                    int target_fd = -1;
                    uint64_t target_session = 0;
                    SSL *target_ssl = NULL;

                    if (ws_registry_get_session_info(target, &target_fd, &target_session, &target_ssl)) {
                        if (ws_registry_validate_session(target_fd, target_session)) {
                            ws_outgoing_frame_t *pending = NULL;
                            ws_system_send_text(target_fd, target_ssl, json_raw, strlen(json_raw), &pending);
                        }
                    }
                }
            }
        }
    }

    json_object_put(parsed_json);
    json_tokener_free(tok);
}

/* ===================================================================
 * 5. SENDER ENGINE & RETRY MECHANISM
 * =================================================================== */

ws_outgoing_frame_t *ws_frame_create_raw(size_t total_length) {
    ws_outgoing_frame_t *frame = malloc(sizeof(ws_outgoing_frame_t));
    if (!frame) return NULL;

    frame->length = total_length;
    frame->offset = 0;
    frame->next   = NULL;
    frame->data   = malloc(total_length);

    if (!frame->data) {
        free(frame);
        return NULL;
    }
    return frame;
}

void ws_frame_free(ws_outgoing_frame_t *frame) {
    if (frame) {
        if (frame->data) free(frame->data);
        free(frame);
    }
}

static ws_send_status_t ws_low_level_send_frame(int sock_client, SSL *ssl, ws_outgoing_frame_t *frame) {
    uint8_t *src = frame->data + frame->offset;
    size_t remaining = frame->length - frame->offset;

    if (ssl) {
        int sent = SSL_write(ssl, src, (int)remaining);
        if (sent <= 0) {
            int err = SSL_get_error(ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                return WS_SEND_RETRY;
            }
            return WS_SEND_FATAL;
        }
        frame->offset += (size_t)sent;
    } else {
        ssize_t sent = send(sock_client, src, remaining, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                return WS_SEND_RETRY;
            }
            return WS_SEND_FATAL;
        }
        frame->offset += (size_t)sent;
    }

    return (frame->offset < frame->length) ? WS_SEND_RETRY : WS_SEND_OK;
}

ws_send_status_t ws_system_send_text(int sock_client, SSL *ssl, const char *text, size_t len, ws_outgoing_frame_t **out_frame) {
    if (out_frame) *out_frame = NULL;
    if (!text && len != 0) return WS_SEND_FATAL;

    uint8_t header[10];
    size_t header_idx = 0;

    header[0] = 0x81; // FIN=1, Opcode=0x1 (Text)

    if (len <= 125) {
        header[1] = (uint8_t)len;
        header_idx = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        uint16_t len_be = htons((uint16_t)len);
        memcpy(header + 2, &len_be, 2);
        header_idx = 4;
    } else {
        header[1] = 127;
        uint64_t len_be = htobe64((uint64_t)len);
        memcpy(header + 2, &len_be, 8);
        header_idx = 10;
    }

    ws_outgoing_frame_t *frame = ws_frame_create_raw(header_idx + len);
    if (!frame) return WS_SEND_FATAL;

    memcpy(frame->data, header, header_idx);
    if (text && len > 0) {
        memcpy(frame->data + header_idx, text, len);
    }

    ws_send_status_t status = ws_low_level_send_frame(sock_client, ssl, frame);

    // Retention Frame jika butuh RETRY
    if (status == WS_SEND_RETRY && out_frame != NULL) {
        *out_frame = frame; 
    } else {
        ws_frame_free(frame); 
    }

    return status;
}

ws_send_status_t ws_system_send_text_h2(int sock_client, uint32_t stream_id, const char *text, ws_outgoing_frame_t **out_frame) {
    if (out_frame) *out_frame = NULL;
    if (!text) return WS_SEND_FATAL;

    size_t len = strlen(text);
    uint8_t ws_header[10];
    size_t ws_header_idx = 0;

    ws_header[0] = 0x81;
    if (len <= 125) {
        ws_header[1] = (uint8_t)len;
        ws_header_idx = 2;
    } else if (len <= 65535) {
        ws_header[1] = 126;
        uint16_t net_len = htons((uint16_t)len);
        memcpy(ws_header + 2, &net_len, 2);
        ws_header_idx = 4;
    } else {
        ws_header[1] = 127;
        uint64_t net_len = htobe64((uint64_t)len);
        memcpy(ws_header + 2, &net_len, 8);
        ws_header_idx = 10;
    }

    size_t ws_total_len = ws_header_idx + len;
    size_t h2_total_len = 9 + ws_total_len;

    ws_outgoing_frame_t *frame = ws_frame_create_raw(h2_total_len);
    if (!frame) return WS_SEND_FATAL;

    // HTTP/2 Frame Framing Layout
    frame->data[0] = (ws_total_len >> 16) & 0xFF;
    frame->data[1] = (ws_total_len >> 8) & 0xFF;
    frame->data[2] = ws_total_len & 0xFF;
    frame->data[3] = 0x00; // Type: DATA
    frame->data[4] = 0x00; // Flags: Tunnel Extended CONNECT Payload

    uint32_t res_stream_id = stream_id & 0x7FFFFFFF;
    frame->data[5] = (res_stream_id >> 24) & 0xFF;
    frame->data[6] = (res_stream_id >> 16) & 0xFF;
    frame->data[7] = (res_stream_id >> 8) & 0xFF;
    frame->data[8] = res_stream_id & 0xFF;

    memcpy(frame->data + 9, ws_header, ws_header_idx);
    memcpy(frame->data + 9 + ws_header_idx, text, len);

    SSL *ssl = ssl_get_for_fd(sock_client);
    ws_send_status_t status = ws_low_level_send_frame(sock_client, ssl, frame);

    if (status == WS_SEND_RETRY && out_frame != NULL) {
        *out_frame = frame;
    } else {
        ws_frame_free(frame);
    }

    return status;
}

ws_send_status_t ws_system_send_retry(int sock_client, SSL *ssl, ws_outgoing_frame_t *frame) {
    if (!frame) return WS_SEND_FATAL;

    ws_send_status_t status = ws_low_level_send_frame(sock_client, ssl, frame);

    if (status == WS_SEND_OK || status == WS_SEND_FATAL) {
        ws_frame_free(frame);
    }

    return status;
}

/* ===================================================================
 * 6. HTTP/2 TUNNEL RECV PARSER & PONG HELPERS
 * =================================================================== */

void ws_system_send_pong_h2(int sock_client, uint32_t stream_id) {
    unsigned char pong_frame[2] = {0x8A, 0x00};
    unsigned char h2_pong[11];
    
    h2_pong[0] = 0x00; h2_pong[1] = 0x00; h2_pong[2] = 0x02;
    h2_pong[3] = 0x00;
    h2_pong[4] = 0x00;
    
    uint32_t res_stream_id = stream_id & 0x7FFFFFFF;
    h2_pong[5] = (res_stream_id >> 24) & 0xFF;
    h2_pong[6] = (res_stream_id >> 16) & 0xFF;
    h2_pong[7] = (res_stream_id >> 8) & 0xFF;
    h2_pong[8] = res_stream_id & 0xFF;
    
    memcpy(h2_pong + 9, pong_frame, 2);
    ws_low_level_send(sock_client, h2_pong, 11);
}

void ws_system_handle_h2_payload(int sock_client, uint32_t stream_id, unsigned char *h2_data, size_t h2_len) {
    if (h2_len < 2 || h2_data == NULL) return;

    int opcode = h2_data[0] & 0x0F;
    bool masked = (h2_data[1] & 0x80) != 0;
    uint64_t ws_payload_len = h2_data[1] & 0x7F;
    size_t header_offset = 2;

    if (ws_payload_len == 126) {
        if (h2_len < 4) return;
        uint16_t ext_len;
        memcpy(&ext_len, h2_data + 2, 2);
        ws_payload_len = ntohs(ext_len);
        header_offset += 2;
    } else if (ws_payload_len == 127) {
        if (h2_len < 10) return;
        uint64_t ext_len;
        memcpy(&ext_len, h2_data + 2, 8);
        ws_payload_len = be64toh(ext_len);
        header_offset += 8;
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (h2_len < header_offset + 4) return;
        memcpy(mask, h2_data + header_offset, 4);
        header_offset += 4;
    }

    if (header_offset + ws_payload_len > h2_len) return;

    unsigned char *clean_json = malloc(ws_payload_len + 1);
    if (!clean_json) return;

    memcpy(clean_json, h2_data + header_offset, ws_payload_len);
    clean_json[ws_payload_len] = '\0';

    if (masked) {
        for (size_t i = 0; i < ws_payload_len; i++) {
            clean_json[i] ^= mask[i % 4];
        }
    }

    switch (opcode) {
        case WS_OP_TEXT:
            ws_system_on_message(sock_client, stream_id, clean_json, ws_payload_len);
            break;

        case WS_OP_PING:
            ws_system_send_pong_h2(sock_client, stream_id);
            break;

        case WS_OP_PONG:
            ws_registry_update_activity(sock_client);
            break;

        case WS_OP_CLOSE:
            ws_system_cleanup_fd(sock_client);
            break;

        default:
            break;
    }

    free(clean_json);
}

/* ===================================================================
 * 7. INTERNAL UTILITIES & BACKGROUND MAINTENANCE
 * =================================================================== */

static char* ws_base64_encode(const unsigned char *input, int length) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *output, *p;
    int i;
    int out_len = 4 * ((length + 2) / 3);

    output = malloc(out_len + 1);
    if (!output) return NULL;

    p = output;
    for (i = 0; i < length - 2; i += 3) {
        *p++ = table[(input[i] >> 2) & 0x3F];
        *p++ = table[((input[i] & 0x3) << 4) | (input[i+1] >> 4)];
        *p++ = table[((input[i+1] & 0xF) << 2) | (input[i+2] >> 6)];
        *p++ = table[input[i+2] & 0x3F];
    }
    if (i < length) {
        *p++ = table[(input[i] >> 2) & 0x3F];
        if (i == (length - 1)) {
            *p++ = table[(input[i] & 0x3) << 4];
            *p++ = '=';
        } else {
            *p++ = table[((input[i] & 0x3) << 4) | (input[i+1] >> 4)];
            *p++ = table[((input[i+1] & 0xF) << 2)];
        }
        *p++ = '=';
    }
    *p = '\0';
    return output;
}

static char* ws_create_accept_key(const char *client_key) {
    if (!client_key) return NULL;

    char combined[256];
    unsigned char sha1_res[SHA_DIGEST_LENGTH];

    snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);
    SHA1((unsigned char*)combined, strlen(combined), sha1_res);
    return ws_base64_encode(sha1_res, SHA_DIGEST_LENGTH);
}

static ssize_t ws_low_level_recv(int fd, void *buf, size_t len) {
    SSL *ssl = ssl_get_for_fd(fd);
    if (ssl != NULL) {
        int n = SSL_read(ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
            }
        }
        return (ssize_t)n;
    }
    return recv(fd, buf, len, MSG_DONTWAIT);
}

static ssize_t ws_low_level_send(int fd, const void *buf, size_t len) {
    SSL *ssl = ssl_get_for_fd(fd);
    if (ssl != NULL) {
        return (ssize_t)SSL_write(ssl, buf, (int)len);
    }
    return send(fd, buf, len, MSG_NOSIGNAL);
}

static void ws_system_send_pong(int sock_client) {
    unsigned char pong_frame[2] = {0x8A, 0x00};
    SSL *ssl = ssl_get_for_fd(sock_client);
    if (ssl) SSL_write(ssl, pong_frame, 2);
    else send(sock_client, pong_frame, 2, MSG_NOSIGNAL);
}

static void* ws_system_maintenance_run(void *arg) {
    (void)arg;
    write_log("[WS-SYSTEM] Background Maintenance Thread Active.");

    while (1) {
        sleep(30);
        ws_registry_heartbeat();
        ws_registry_reaper();
    }
    return NULL;
}