#ifndef HALMOS_HTTP2_CORE_H
#define HALMOS_HTTP2_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>             // Wajib ada karena kamu pakai pthread_mutex_t
#include "halmos_http1_header.h" 

/* --- HTTP/2 FRAME TYPES --- */
#define HTTP2_FRAME_DATA          0x0
#define HTTP2_FRAME_HEADERS       0x1
#define HTTP2_FRAME_PRIORITY      0x2
#define HTTP2_FRAME_RST_STREAM    0x3
#define HTTP2_FRAME_SETTINGS      0x4
#define HTTP2_FRAME_PUSH_PROMISE  0x5
#define HTTP2_FRAME_PING          0x6
#define HTTP2_FRAME_GOAWAY        0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION  0x9

/* --- FRAME FLAGS --- */
#define HTTP2_FLAG_END_STREAM     0x01
#define HTTP2_FLAG_ACK            0x01
#define HTTP2_FLAG_END_HEADERS    0x04
#define HTTP2_FLAG_PADDED         0x08
#define HTTP2_FLAG_PRIORITY       0x20

/**
 * Representasi Header Frame HTTP/2 (9 Bytes)
 */
typedef struct {
    uint32_t length;     // 24-bit
    uint8_t  type;       // 8-bit
    uint8_t  flags;      // 8-bit
    uint32_t stream_id;  // 31-bit
} HTTP2FrameHeader;

/**
 * State sebuah Stream (RFC 7540)
 */
typedef enum {
    HTTP2_STATE_IDLE,
    HTTP2_STATE_RESERVED_LOCAL,
    HTTP2_STATE_RESERVED_REMOTE,
    HTTP2_STATE_OPEN,
    HTTP2_STATE_HALF_CLOSED_LOCAL,
    HTTP2_STATE_HALF_CLOSED_REMOTE,
    HTTP2_STATE_CLOSED
} HTTP2StreamState;

/**
 * HPACK Dynamic Table Entry
 */
typedef struct {
    char *name;
    char *value;
    uint32_t entry_size; // Dihitung: name_len + value_len + 32 (RFC overhead)
} HPACKEntry;

/**
 * Manajemen Dynamic Table per Koneksi
 */
typedef struct {
    HPACKEntry *entries;      // Array dinamis untuk menyimpan header
    uint32_t count;           // Jumlah entri saat ini
    uint32_t max_entries;     // Kapasitas slot (misal: 128)
    uint32_t current_size;    // Total size dalam bytes
    uint32_t max_size;        // Batas byte (Default: 4096)
} HPACKDynamicTable;

/**
 * RequestHeader versi H2 (Satu stream = Satu request)
 */
typedef struct HTTP2Stream {
    uint32_t stream_id;
    HTTP2StreamState state;
    
    // Reuse arsitektur RequestHeader Halmos (Zero-copy)
    RequestHeader http1_compat; 
    
    int32_t window_size;
    struct HTTP2Stream *next; // Point ke stream aktif lainnya
} HTTP2Stream;

/**
 * Konteks per satu Koneksi TCP (Session)
 */
typedef struct {
    int fd;
    bool is_tls;

    /* --- HPACK STATE --- */
    HPACKDynamicTable dyn_table;
    
    // Lock ini krusial untuk sinkronisasi state HPACK antar thread
    pthread_mutex_t hpack_lock;

    /* --- STREAM MANAGEMENT (Multiplexing) --- */
    HTTP2Stream *streams;
    pthread_mutex_t streams_lock; 
    
    uint32_t last_stream_id;
    int32_t  remote_window_size;
    int32_t  local_window_size;
} HTTP2Session;

#endif