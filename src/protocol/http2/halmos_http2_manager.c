#include "halmos_http2_manager.h"
#include "halmos_global.h"
#include "halmos_core_config.h"

#include "halmos_http2_parser.h"
#include "halmos_http2_response.h"

#include "halmos_http2_frame.h"
#include "halmos_http2_socket.h"

#include "halmos_sec_tls.h"
#include "halmos_log.h"
 
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <fcntl.h>      // Untuk open, O_RDONLY
#include <sys/stat.h>   // Untuk stat, struct stat, S_ISDIR
#include <sys/types.h>

/* Helper http2_manager_session */
static bool session_init(halmos_conn_t *conn);
static int handle_socket_retry(HTTP2Session *session, bool is_tls, halmos_conn_t *conn, ssize_t n);
static int process_preface(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn);
static int read_frame_header(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn);
static int read_frame_payload(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn);
static int dispatch_frame(HTTP2Session *session, int sock_client, bool is_tls);

int http2_manager_session(halmos_conn_t *conn) {
    if (!session_init(conn)) return 0;
    
    HTTP2Session *session = (HTTP2Session *)conn->protocol_session;
    int sock_client = conn->fd;
    bool is_tls = session->is_tls;
 
    while (1) {
        // === Flush write backlog & cek hard error SEBELUM apa pun ===
        if (session->write_error) {
            return 0; 
        }
        if (session->pending_write_len > session->pending_write_offset) {
            int flush_status = http2_socket_flush_pending_write(session);
            if (flush_status < 0) return 0; 
            if (flush_status > 0) return 4; // Minta EPOLLIN|EPOLLOUT
        }
 
        // === Konsumsi Client Connection Preface (24 byte) ===
        int preface_res = process_preface(session, sock_client, is_tls, conn);
        if (preface_res == 0) return 0;
        if (preface_res == 2 || preface_res == 4) return preface_res;
        if (preface_res == 1 && session->preface_bytes_read < 24) continue;
 
        http2_response_flush_active_streams(session);
 
        // === Baca Frame Header (9 byte) ===
        int header_res = read_frame_header(session, sock_client, is_tls, conn);
        if (header_res == 0) return 0;
        if (header_res == 2 || header_res == 4) return header_res;
        if (session->read_state == 0) continue;
 
        // === Baca Frame Payload & Proses Frame ===
        int payload_res = read_frame_payload(session, sock_client, is_tls, conn);
        if (payload_res == 0) return 0;
        if (payload_res == 2) continue; // Lanjut loop baca payload
        if (payload_res == 4) return 4;
        
        // Frame sudah lengkap, dispatch
        int dispatch_res = dispatch_frame(session, sock_client, is_tls);
        if (dispatch_res == 0) return 0;
    }
    
    // Return akhir sesi (jika loop selesai/keluar)
    bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                      http2_response_has_active_streams(session);
    return need_write ? 4 : 1;
}

void http2_session_destroy(void *sess) {
    HTTP2Session *session = (HTTP2Session *)sess;
    if (!session) return;
    
    // Kirim goaway jika diperlukan (opsional, karena socket mungkin sudah putus)
 
    for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) { 
        HTTP2Stream *curr = session->streams_hash[i];
        while (curr != NULL) {
            HTTP2Stream *next_node = curr->node_next; 
 
            if (curr->file_fd >= 0) {
                close(curr->file_fd);
                curr->file_fd = -1;
            }
 
            if (curr->http1_compat.body_data) {
                free(curr->http1_compat.body_data);
                curr->http1_compat.body_data = NULL;
            }
            http2_parser_free_memory(curr);
            free(curr);
            curr = next_node;
        }
        session->streams_hash[i] = NULL;
    }
 
    if (session->dyn_table.entries) {
        free(session->dyn_table.entries);
        session->dyn_table.entries = NULL;
    }
    
    if (session->payload_buf) {
        free(session->payload_buf);
        session->payload_buf = NULL;
    }
 
    // === TAMBAHAN: bereskan sisa write backlog kalau koneksi ditutup di tengah ===
    if (session->pending_write_buf) {
        free(session->pending_write_buf);
        session->pending_write_buf = NULL;
    }
 
    pthread_mutex_destroy(&session->hpack_lock);
    pthread_mutex_destroy(&session->streams_lock);
    free(session);
}

/*
Private (Helper)
*/

//Paket Helper http2_manager_session
// Helper http2_manager_session 1: Inisialisasi sesi HTTP/2 baru jika belum ada
bool session_init(halmos_conn_t *conn) {
    if (!conn->protocol_session) {
        HTTP2Session *session = calloc(1, sizeof(HTTP2Session));
        if (!session) return false;
        
        session->fd = conn->fd;
        session->is_tls = (conn->ssl != NULL);
        session->out_window_size = 65535;
        session->dyn_table.entries = calloc(128, sizeof(HPACKEntry));
        session->peer_initial_window_size = 65535;
        session->dyn_table.max_size = 4096; 
        
        pthread_mutex_init(&session->hpack_lock, NULL);
        pthread_mutex_init(&session->streams_lock, NULL);
        
        conn->protocol_session = session;
        conn->protocol_session_destroy = http2_session_destroy;
        
        http2_frame_send_settings(conn->fd, session->is_tls);
    }
    return true;
}

// Helper http2_manager_session 2: Penanganan error retry koneksi socket (EAGAIN/WANT_READ/WANT_WRITE)
int handle_socket_retry(HTTP2Session *session, bool is_tls, halmos_conn_t *conn, ssize_t n) {
    bool retry = false;
    if (is_tls) {
        int err = SSL_get_error(conn->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) retry = true;
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        retry = true;
    }
    if (retry) {
        bool need_write = (session->pending_write_len > session->pending_write_offset) || 
                          http2_response_has_active_streams(session);
        return need_write ? 4 : 2;
    }
    return 0;
}

// Helper http2_manager_session 3: Membaca dan mengonsumsi Client Connection Preface (24 byte pertama)
int process_preface(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn) {
    if (session->preface_bytes_read < 24) {
        unsigned char discard_buf[24];
        size_t to_read = 24 - session->preface_bytes_read;
        ssize_t n = http2_socket_read(sock_client, is_tls, discard_buf, to_read);

        if (n > 0) {
            session->preface_bytes_read += n;
            if (session->preface_bytes_read < 24) {
                return 1; // Lanjutkan loop baca
            }
        } else if (n < 0) {
            return handle_socket_retry(session, is_tls, conn, n);
        } else {
            return 0; // EOF / preface terpotong
        }
    }
    return 1;
}

// Helper http2_manager_session 4: Membaca 9 byte frame header HTTP/2
int read_frame_header(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn) {
    if (session->read_state == 0) {
        size_t to_read = 9 - session->header_bytes_read;
        ssize_t n = http2_socket_read(sock_client, is_tls, session->header_buf_partial + session->header_bytes_read, to_read);
        
        if (n > 0) {
            session->header_bytes_read += n;
            if (session->header_bytes_read == 9) {
                if (!http2_parser_frame_header(session->header_buf_partial, &session->current_frame_head)) {
                    return 0; 
                }
                session->read_state = 1;
                session->payload_bytes_read = 0;
                if (session->current_frame_head.length > 0) {
                    size_t max_allowed_payload = (config.max_body_size > 0) ? config.max_body_size : 1048576;
                    if (session->current_frame_head.length > max_allowed_payload) {
                        write_log_error("[H2-ERROR] Frame payload length %u exceeds limit (%zu) on FD %d", 
                                        session->current_frame_head.length, max_allowed_payload, sock_client);
                        return 0; 
                    }
                    session->payload_buf = malloc(session->current_frame_head.length);
                    if (!session->payload_buf) return 0;
                }
            }
        } else if (n < 0) {
            return handle_socket_retry(session, is_tls, conn, n);
        } else {
            if (session->header_bytes_read == 0) return 0; 
            return 0; 
        }
    }
    return 1;
}

// Helper http2_manager_session 5: Membaca payload frame HTTP/2
int read_frame_payload(HTTP2Session *session, int sock_client, bool is_tls, halmos_conn_t *conn) {
    if (session->read_state == 1) {
        if (session->current_frame_head.length > 0) {
            size_t to_read = session->current_frame_head.length - session->payload_bytes_read;
            ssize_t n = http2_socket_read(sock_client, is_tls, session->payload_buf + session->payload_bytes_read, to_read);
            
            if (n > 0) {
                session->payload_bytes_read += n;
                if (session->payload_bytes_read < session->current_frame_head.length) {
                    return 2; // Lanjutkan loop (continue)
                }
            } else if (n < 0) {
                return handle_socket_retry(session, is_tls, conn, n);
            } else {
                return 0; 
            }
        }
    }
    return 1;
}

// Helper http2_manager_session 6: Menangani dispatch frame berdasarkan tipenya (RST_STREAM, SETTINGS, PING, WINDOW_UPDATE, dll)
int dispatch_frame(HTTP2Session *session, int sock_client, bool is_tls) {
    HTTP2FrameHeader *head = &session->current_frame_head;
    unsigned char *payload = session->payload_buf;
    
    switch (head->type) {
        case 0x00: http2_parser_handle_data(session, head, payload); break;
        case 0x01: http2_parser_handle_headers(session, head, payload); break;
        case 0x03: {
            pthread_mutex_lock(&session->streams_lock);
            for (int i = 0; i < HTTP2_STREAM_BUCKETS; i++) {
                HTTP2Stream *curr = session->streams_hash[i];
                while (curr != NULL) {
                    if (curr->stream_id == head->stream_id) {
                        if (curr->file_fd >= 0) {
                            close(curr->file_fd);
                            curr->file_fd = -1;
                        }
                        curr->is_sending_file = false;
                        curr->state = HTTP2_STATE_CLOSED;
                        break;
                    }
                    curr = curr->node_next;
                }
            }
            pthread_mutex_unlock(&session->streams_lock);
            break;
        }
        case 0x04:
            if (!(head->flags & 0x01) && payload && head->length >= 6) {
                for (uint32_t idx = 0; idx + 6 <= head->length; idx += 6) {
                    uint16_t id = (payload[idx] << 8) | payload[idx + 1];
                    uint32_t val = (payload[idx + 2] << 24) | (payload[idx + 3] << 16) | (payload[idx + 4] << 8) | payload[idx + 5];
                    if (id == 0x0004) {
                        int32_t delta = (int32_t)val - (int32_t)session->peer_initial_window_size;
                        session->peer_initial_window_size = val;
                        pthread_mutex_lock(&session->streams_lock);
                        for (int b = 0; b < HTTP2_STREAM_BUCKETS; b++) {
                            HTTP2Stream *s = session->streams_hash[b];
                            while (s) { s->out_window_size += delta; s = s->node_next; }
                        }
                        pthread_mutex_unlock(&session->streams_lock);
                    }
                }
                http2_frame_send_settings_ack(sock_client, is_tls);
            }
            break;
        case 0x06:
            if ((head->flags & 0x01) == 0) http2_frame_send(sock_client, is_tls, 0x06, 0x01, 0, payload, head->length);
            break;
        case 0x07:
            return 0; // GOAWAY
        case 0x08:
            http2_frame_handle_window_update(session, head, payload);
            break;
    }
    
    if (session->payload_buf) {
        free(session->payload_buf);
        session->payload_buf = NULL;
    }
    
    session->read_state = 0;
    session->header_bytes_read = 0;
    return 1;
}
//Akhir paket Helper http2_manager_session
