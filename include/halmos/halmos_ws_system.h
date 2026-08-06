#ifndef HALMOS_WS_SYSTEM_H
#define HALMOS_WS_SYSTEM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>

#include "halmos_http1_parser.h"

// 1. Status Send
typedef enum {
    WS_SEND_OK    =  0,
    WS_SEND_RETRY = -2,
    WS_SEND_FATAL = -1
} ws_send_status_t;

// 2. Status Recv (Dibutuhkan oleh halmos_ws_recv_frame)
typedef enum {
    WS_RECV_OK    =  0,
    WS_RECV_AGAIN = -2,
    WS_RECV_FATAL = -1
} ws_recv_status_t;

// 3. Struct Outgoing Frame (Dilengkapi pointer 'next' untuk queue frame)
typedef struct ws_outgoing_frame {
    unsigned char *data;
    size_t length;
    size_t offset;
    struct ws_outgoing_frame *next;
} ws_outgoing_frame_t;

// 4. Opcode sesuai RFC 6455 (Didefinisikan SEBELUM ws_context_t)
typedef enum {
    WS_OP_CONT  = 0x0,
    WS_OP_TEXT  = 0x1,
    WS_OP_BIN   = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING  = 0x9,
    WS_OP_PONG  = 0xA
} ws_opcode_t;

// 5. State machine parser
typedef enum {
    WS_STATE_HEADER,
    WS_STATE_EXT_LEN,
    WS_STATE_MASK,
    WS_STATE_PAYLOAD,
    WS_STATE_COMPLETE
} ws_state_t;

// Alias ws_recv_step_t agar cocok dengan pemanggilan lama di .c
typedef ws_state_t ws_recv_step_t;

// 6. Struct context WebSocket
typedef struct {
    ws_state_t state;
    ws_opcode_t opcode;
    bool fin;
    bool masked;
    uint8_t mask_key[4];
    uint64_t payload_len;
    uint64_t bytes_received;
    unsigned char *payload_buf;
} ws_context_t;

typedef enum {
    ACT_UNKNOWN = 0,
    ACT_AUTH,
    ACT_PRIVATE,
    ACT_BROADCAST,
    ACT_GROUP,
    ACT_PUB,
    ACT_SUB,
    ACT_REQ
} ws_action_ipc_t;

// IPC Constants
#define K_HEADER  "header"
#define K_PAYLOAD "payload"
#define K_ACTION  "type"
#define K_SRC     "src"
#define K_DST     "dst"
#define K_APP     "app_id" 

#define INTERNAL_PREFIX "HALMOS_"
#define SOCKET_PATH     "/tmp/halmos_bridge.sock"

void halmos_set_websocket_fd(int fd, bool status);
bool halmos_is_websocket_fd(int fd);

bool ws_is_upgrade_request(RequestHeader *req);
int ws_upgrade_handshake(int sock_client, RequestHeader *req);

int ws_system_dispatch(int sock_client);
void ws_system_internal_dispatch(const char *json_raw);

ws_send_status_t ws_system_send_text(int sock_client, SSL *ssl, const char *text, size_t len, ws_outgoing_frame_t **out_frame);
ws_send_status_t ws_system_send_text_h2(int sock_client, uint32_t stream_id, const char *text, ws_outgoing_frame_t **out_frame);

void ws_system_send_pong_h2(int sock_client, uint32_t stream_id);
void ws_system_handle_h2_payload(int sock_client, uint32_t stream_id, unsigned char *h2_data, size_t h2_len);

void ws_system_on_message(int sock_client, uint32_t stream_id, unsigned char *data, size_t len);

void halmos_ws_system_init(void);
void ws_system_cleanup_fd(int fd);
void ws_system_destroy(void);

#endif /* HALMOS_WS_SYSTEM_H */