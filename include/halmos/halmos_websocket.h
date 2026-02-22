#ifndef HALMOS_WEBSOCKET_H
#define HALMOS_WEBSOCKET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
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
int halmos_ws_dispatch(int sock_client);

// Fungsi untuk mengirim pesan teks (Otomatis bungkus frame)
int halmos_ws_send_text(int sock_client, const char *text);

/**
 * LOGIKA BISNIS (JSON-C)
 */
// Di sinilah tempat lu naro logika JSON karangan lu
void halmos_ws_on_message(int sock_client, unsigned char *data, size_t len);

void halmos_ws_system_init();

void halmos_ws_cleanup_fd(int fd);

void halmos_ws_system_destroy();
#endif