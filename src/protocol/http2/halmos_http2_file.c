#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_http2_file.h"
#include "halmos_http2_core.h"
#include "halmos_http2_stream.h"
#include "halmos_http2_frame.h"

#include <unistd.h>            // Untuk pread() dan close()
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>

#define HTTP2_MAX_FRAME_SIZE 16384

void http2_file_flush_active_streams(HTTP2Session *session) {
    if (!session) return;
 
    uint32_t active_ids[256];
    int active_count = 0;
 
    // 1. Kumpulkan stream aktif under lock
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            if (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED) {
                if (active_count < 256) {
                    active_ids[active_count++] = curr->stream_id;
                }
            }
            curr = curr->node_next;
        }
    }
    pthread_mutex_unlock(&session->streams_lock);
 
    // 2. Iterasi stream dan periksa Flow Control Credit
    for (int k = 0; k < active_count; k++) {
        uint32_t target_sid = active_ids[k];
        
        int file_fd = -1;
        off_t offset = 0;
        off_t total_size = 0;
        int32_t conn_win = 0;
        int32_t stream_win = 0;
        bool valid = false;
 
        // Ambil snapshot metadata & window credit
        pthread_mutex_lock(&session->streams_lock);
        HTTP2Stream *st = http2_stream_find_unlocked(session, target_sid);
        if (st && st->is_sending_file && st->file_fd >= 0 && st->state != HTTP2_STATE_CLOSED) {
            file_fd = st->file_fd;
            offset = st->file_offset;
            total_size = st->file_size;
            conn_win = session->out_window_size;
            stream_win = st->out_window_size;
            valid = true;
        }
        pthread_mutex_unlock(&session->streams_lock);
 
        if (!valid || file_fd < 0 || offset >= total_size) continue;
 
        // CHECK 1: Apabila connection window atau stream window habis (<= 0), tunda pengiriman!
        if (conn_win <= 0 || stream_win <= 0) {
            //fprintf(stderr, "[H2-FLOW-CONTROL] Stalled Stream %u | Conn Window: %d, Stream Window: %d\n", 
            //        target_sid, conn_win, stream_win);
            continue; // Skip stream ini sampai client mengirim WINDOW_UPDATE
        }
 
        // Hitung sisa bytes di disk
        off_t bytes_remaining = total_size - offset;
 
        // CHECK 2: Cari nilai terkecil antara MAX_FRAME_SIZE, Conn Window, Stream Window, dan sisa File
        uint32_t max_allowed = HTTP2_MAX_FRAME_SIZE; 
        if ((int32_t)max_allowed > conn_win) max_allowed = (uint32_t)conn_win;
        if ((int32_t)max_allowed > stream_win) max_allowed = (uint32_t)stream_win;
        if ((off_t)max_allowed > bytes_remaining) max_allowed = (uint32_t)bytes_remaining;
 
        if (max_allowed == 0) continue;
 
        // Baca disk secara Non-blocking via pread
        unsigned char buf[HTTP2_MAX_FRAME_SIZE];
        ssize_t n_read = pread(file_fd, buf, max_allowed, offset);
 
        if (n_read <= 0) {
            pthread_mutex_lock(&session->streams_lock);
            st = http2_stream_find_unlocked(session, target_sid);
            if (st) {
                if (st->file_fd >= 0) close(st->file_fd);
                st->file_fd = -1;
                st->is_sending_file = false;
                st->state = HTTP2_STATE_CLOSED;
            }
            pthread_mutex_unlock(&session->streams_lock);
            continue;
        }
 
        uint8_t flags = 0x00;
        if ((offset + n_read) >= total_size) {
            flags = 0x01; // END_STREAM
        }
 
        // Kirim frame DATA ke socket
        http2_frame_send(session->fd, session->is_tls, 0x00, flags, target_sid, buf, (uint32_t)n_read);
 
        // CHECK 3: Potong (deduct) kredit window sejumlah byte payload yang dikirim (n_read)
        pthread_mutex_lock(&session->streams_lock);
        session->out_window_size -= (int32_t)n_read;
        
        st = http2_stream_find_unlocked(session, target_sid);
        if (st) {
            st->out_window_size -= (int32_t)n_read;
            st->file_offset += n_read;
            if (st->file_offset >= st->file_size) {
                if (st->file_fd >= 0) close(st->file_fd);
                st->file_fd = -1;
                st->is_sending_file = false;
                st->state = HTTP2_STATE_CLOSED;
            }
        }
        pthread_mutex_unlock(&session->streams_lock);
    }
}

bool http2_file_has_active_streams(HTTP2Session *session) {
    if (!session) return false;
    bool has_file = false;
 
    pthread_mutex_lock(&session->streams_lock);
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            if (curr->is_sending_file && curr->file_fd >= 0 && curr->state != HTTP2_STATE_CLOSED) {
                has_file = true;
                break;
            }
            curr = curr->node_next;
        }
        if (has_file) break;
    }
    pthread_mutex_unlock(&session->streams_lock);
    
    return has_file;
}
