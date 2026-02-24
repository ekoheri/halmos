#ifndef HALMOS_WS_SYSTEM_H
#define HALMOS_WS_SYSTEM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>

#include "halmos_http1_parser.h" // Kita butuh RequestHeader buat handshake

// Opcode sesuai RFC 6455
typedef enum {
    WS_OP_CONT  = 0x0,
    WS_OP_TEXT  = 0x1,
    WS_OP_BIN   = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING  = 0x9,
    WS_OP_PONG  = 0xA
} ws_opcode_t;

// State machine untuk menangani partial frame (data kepotong di epoll)
typedef enum {
    WS_STATE_HEADER,
    WS_STATE_EXT_LEN,
    WS_STATE_MASK,
    WS_STATE_PAYLOAD,
    WS_STATE_COMPLETE
} ws_state_t;

// Struct untuk menyimpan context per koneksi WebSocket
// Ini nanti diselipkan di mapping FD lu
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

// Konstanta untuk IPC
#define K_HEADER  "header"
#define K_PAYLOAD "payload"
#define K_ACTION  "action"
#define K_SRC     "src"
#define K_DST     "dst"
#define K_APP     "app" 
// --- Aturan Keamanan & IPC ---
#define INTERNAL_PREFIX "HALMOS_"
#define SOCKET_PATH     "/tmp/halmos_bridge.sock"

void halmos_set_websocket_fd(int fd, bool status);

bool halmos_is_websocket_fd(int fd);
/**
 * HANDSHAKE LOGIC
 */
// Cek apakah request HTTP ingin upgrade ke WS
bool ws_is_upgrade_request(RequestHeader *req);

// Proses jabat tangan dan kirim respon 101
int ws_upgrade_handshake(int sock_client, RequestHeader *req);

/**
 * FRAME HANDLING (NON-BLOCKING)
 */
// Fungsi utama yang dipanggil oleh Worker Thread saat ada event EPOLLIN
// Return 1 untuk lanjut (rearm), 0 untuk tutup (cleanup)
int ws_system_dispatch(int sock_client);

void ws_system_internal_dispatch(const char *json_raw);

// Fungsi untuk mengirim pesan teks (Otomatis bungkus frame)
int ws_system_send_text(int sock_client, SSL *ssl, const char *text);

/**
 * LOGIKA BISNIS (JSON-C)
 */
// Di sinilah tempat lu naro logika JSON karangan lu
void ws_system_on_message(int sock_client, unsigned char *data, size_t len);

void halmos_ws_system_init();

void ws_system_cleanup_fd(int fd);

void ws_system_destroy();
#endif