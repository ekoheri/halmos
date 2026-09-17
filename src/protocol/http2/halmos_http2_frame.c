#include "halmos_http2_frame.h"
#include "halmos_http2_core.h"
#include "halmos_http2_stream.h"
#include "halmos_http2_socket.h"
#include "halmos_core_conn_table.h"
#include "halmos_log.h"

#include <string.h>                // Untuk memcpy
#include <stdio.h>
#include <stdlib.h>

void http2_frame_send(int fd, bool is_tls, uint8_t type, uint8_t flags, uint32_t stream_id, const void *payload, uint32_t len) {
    unsigned char total_buf[16384 + 9]; 
    if (len > 16384) return; 
 
    // Header 9 Byte
    total_buf[0] = (len >> 16) & 0xFF;
    total_buf[1] = (len >> 8) & 0xFF;
    total_buf[2] = len & 0xFF;
    total_buf[3] = type;
    total_buf[4] = flags;
    
    uint32_t sid = stream_id & 0x7FFFFFFF;
    total_buf[5] = (sid >> 24) & 0xFF;
    total_buf[6] = (sid >> 16) & 0xFF;
    total_buf[7] = (sid >> 8) & 0xFF;
    total_buf[8] = sid & 0xFF;
 
    if (len > 0 && payload != NULL) {
        memcpy(total_buf + 9, payload, len);
    }
 
    // === PERBAIKAN: dulu satu kali http2_socket_write() langsung, kalau partial/EAGAIN
    // cuma di-log lalu SISA DATANYA HILANG (frame korup/hilang diam-diam saat
    // client lambat atau window kecil). Sekarang selalu lewat
    // http2_socket_write_or_buffer() yang menyimpan sisa yang belum terkirim ke
    // session->pending_write_buf untuk di-flush di iterasi loop berikutnya,
    // menjaga urutan byte frame tetap benar.
    halmos_conn_t *conn = core_conn_t_get(fd);
    HTTP2Session *session = (conn) ? (HTTP2Session *)conn->protocol_session : NULL;
 
    if (!session) {
        // Fallback: seharusnya tidak terjadi di jalur normal (session selalu
        // ada sebelum http2_frame_send dipanggil), tapi jaga-jaga saja.
        ssize_t total_sent = http2_socket_write(fd, is_tls, total_buf, len + 9);
        if (total_sent < (ssize_t)(len + 9)) {
            write_log_error("[H2-SOCKET] Partial write (no session context) on frame type 0x%02X", type);
        }
        return;
    }
 
    http2_socket_write_or_buffer(session, fd, is_tls, total_buf, len + 9);
}

void http2_frame_send_settings(int fd, bool is_tls) {
    // SETTINGS Frame dengan INITIAL_WINDOW_SIZE (0x0004) dikirim 1 MB (0x00100000)
    unsigned char settings[] = {
        0x00, 0x00, 0x12,       // Payload Length: 18 bytes (3 settings)
        0x04,                   // Frame Type: SETTINGS (0x04)
        0x00,                   // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0
 
        0x00, 0x01,             // Setting ID: 0x0001 (HEADER_TABLE_SIZE)
        0x00, 0x00, 0x00, 0x00, // Value: 0
 
        0x00, 0x03,             // Setting ID: 0x0003 (MAX_CONCURRENT_STREAMS)
        0x00, 0x00, 0x00, 0x64, // Value: 100
 
        0x00, 0x04,             // Setting ID: 0x0004 (INITIAL_WINDOW_SIZE)
        0x00, 0x10, 0x00, 0x00  // Value: 1,048,576 bytes (1 MB Window Size)
    };
    
    //fprintf(stderr, "[H2-SESSION] Sending Initial SETTINGS Frame (27 bytes)...\n");
    http2_socket_write(fd, is_tls, settings, 27);
}

void http2_frame_send_settings_ack(int fd, bool is_tls){
    unsigned char ack[9] = {0,0,0, 4, 1, 0,0,0,0}; 
    http2_socket_write(fd, is_tls, ack, 9);
}

void http2_frame_send_window_update(int fd, bool is_tls, uint32_t stream_id, uint32_t increment) {
    unsigned char payload[4];
    payload[0] = (increment >> 24) & 0x7F;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >> 8) & 0xFF;
    payload[3] = increment & 0xFF;
    http2_frame_send(fd, is_tls, 0x08, 0x00, stream_id, payload, 4);
}

void http2_frame_handle_window_update(HTTP2Session *session, HTTP2FrameHeader *head, const unsigned char *payload) {
    if (!session || !payload || head->length < 4) return;
 
    // Byte ke-0 di-AND dengan 0x7F untuk mengabaikan Reserved Bit (R)
    uint32_t increment = ((payload[0] & 0x7F) << 24) |
                         (payload[1] << 16) |
                         (payload[2] << 8)  |
                          payload[3];
 
    if (increment == 0) {
        // RFC 7540 Section 6.9: Increment 0 adalah PROTOCOL_ERROR
        write_log_error("[H2-WINDOW] Error: Window update increment of 0 on stream %u", head->stream_id);
        return;
    }
 
    pthread_mutex_lock(&session->streams_lock);
 
    if (head->stream_id == 0) {
        // Stream ID 0 -> Connection-level Window
        session->out_window_size += increment;
        //fprintf(stderr, "[H2-WINDOW] Connection Window Updated -> New Credit: %d bytes\n", session->out_window_size);
    } else {
        // Stream ID > 0 -> Stream-level Window
        HTTP2Stream *st = http2_stream_find_unlocked(session, head->stream_id);
        if (st) {
            st->out_window_size += increment;
            //fprintf(stderr, "[H2-WINDOW] Stream %u Window Updated -> New Credit: %d bytes\n", 
            //        head->stream_id, st->out_window_size);
        }
    }
 
    pthread_mutex_unlock(&session->streams_lock);
}

