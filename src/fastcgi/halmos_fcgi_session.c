#include "halmos_fcgi_session.h" // Header definisikan struktur FCGISession & State
#include "halmos_fcgi_pool.h"
#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_global.h"
#include "halmos_http2_core.h"
#include "halmos_http2_response.h"
#include "halmos_http_utils.h"
#include "halmos_http_vhost.h"
#include "halmos_sec_traffic.h"
#include "halmos_sec_tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <poll.h>

#ifndef GATHER_BUF_SIZE
#define GATHER_BUF_SIZE 65536
#endif

static int fcgi_set_socket_nonblocking(int fd);

/**
 * Connection Acquire dipanggil di dalam Fungsi Create
 */
FCGISession *fcgi_session_http1_create(int client_sock, int backend_type, RequestHeader *req, void *post_data, size_t content_length, int request_id) {
    FCGISession *session = (FCGISession *)malloc(sizeof(FCGISession));
    if (!session) return NULL;

    memset(session, 0, sizeof(FCGISession));
    
    session->client_sock = client_sock;
    session->req = req;
    session->post_data = post_data;
    session->content_length = content_length;
    session->request_id = request_id;
    session->g_ptr = 0;
    session->g_sent = 0;
    session->stdin_sent = 0;
    session->state = FCGI_SES_STATE_INIT;

    // 1. AMBIL KONEKSI FPM DI AWAL PEMBUATAN SESI
    // 1. Siapkan pointer
    UpstreamGroup *live_group;   // Data dinamis (next_idx) di fcgi_pool
    BackendGroup  *cfg_group;    // Data statis (ips, ports) dari config/vhost
    
    // --- [TAMBAHAN LOGIKA VHOST OVERRIDE] ---
    // Cari tahu ini request untuk domain apa
    VHostEntry *vh = req->vhost_context; 

    // 2. Mapping & Seleksi Grup (VHost vs Global)
    if (backend_type == 0) { // PHP
        live_group = &fcgi_pool.php_group;
        // Gunakan VHost PHP jika node_count > 0, jika tidak pakai Global
        cfg_group  = (vh && vh->php.node_count > 0) ? &vh->php : &config.php;
    } else if (backend_type == 1) { // RUST
        live_group = &fcgi_pool.rust_group;
        cfg_group  = (vh && vh->rust.node_count > 0) ? &vh->rust : &config.rust;
    } else { // PYTHON
        live_group = &fcgi_pool.python_group;
        cfg_group  = (vh && vh->python.node_count > 0) ? &vh->python : &config.python;
    }

    // 3. Validasi: pastikan ada node yang tersedia
    if (cfg_group->node_count <= 0) {
        write_log_error("[FCGI] No nodes configured for backend type %d", backend_type);
        return NULL;
    }

    /*
    [TIANG UTAMA: LOAD BALANCER]
    Idx dipilih dari cfg_group yang sudah terseleksi (bisa milik VHost atau Global).
    */
    int idx;
    if (strcmp(cfg_group->lb_strategy, "ip_hash") == 0) {
        idx = hash_ip(req->client_ip) % cfg_group->node_count;
    } else {
        // next_idx tetap global per tipe backend agar distribusi merata
        idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    }
    
    // Ambil IP dan Port spesifik dari cfg_group terpilih
    const char *selected_ip = cfg_group->ips[idx];
    int selected_port       = cfg_group->ports[idx];

    session->fpm_sock = fcgi_pool_conn_acquire(selected_ip, selected_port);
    if (session->fpm_sock < 0) {
        write_log_error("[FCGI-SES] Gagal mengambil koneksi dari FPM pool untuk URI: %s", req->uri ? req->uri : "/");
        free(session);
        return NULL; // Batalkan sesi jika pool kosong/gagal
    }

    // Ubah socket backend menjadi non-blocking untuk arsitektur FSM
    fcgi_set_socket_nonblocking(session->fpm_sock);

    // 2. RACIK HEADER (BEGIN REQUEST & PARAMS) KE DALAM GATHER_BUF
    // A. Begin Request
    HalmosFCGI_Header *h = (HalmosFCGI_Header*)&session->gather_buf[session->g_ptr];
    memset(h, 0, sizeof(HalmosFCGI_Header));
    h->version = FCGI_VERSION_1;
    h->type = FCGI_BEGIN_REQUEST;
    h->requestIdB0 = request_id & 0xFF;
    h->requestIdB1 = (request_id >> 8) & 0xFF;
    h->contentLengthB0 = 8;
    session->g_ptr += sizeof(HalmosFCGI_Header);
    
    session->gather_buf[(session->g_ptr)++] = 0;             // Role Responder B1
    session->gather_buf[(session->g_ptr)++] = FCGI_RESPONDER;// Role Responder B0
    session->gather_buf[(session->g_ptr)++] = FCGI_KEEP_CONN;// Keep Conn Flag
    memset(&session->gather_buf[session->g_ptr], 0, 5); 
    session->g_ptr += 5;

    // B. Build Params (Menggunakan fungsi builder dari fcgi_proto.c)
    fcgi_proto_build_params(req, client_sock, content_length, session->gather_buf, &session->g_ptr, request_id);

    return session;
}

int fcgi_session_http2_create(RequestHeader *req, int backend_type){
    UpstreamGroup *live_group;
    BackendGroup  *cfg_group;
    VHostEntry *vh = req->vhost_context; 

    if (backend_type == 0) { // PHP
        live_group = &fcgi_pool.php_group;
        cfg_group  = (vh && vh->php.node_count > 0) ? &vh->php : &config.php;
    } else if (backend_type == 1) { // RUST
        live_group = &fcgi_pool.rust_group;
        cfg_group  = (vh && vh->rust.node_count > 0) ? &vh->rust : &config.rust;
    } else { // PYTHON
        live_group = &fcgi_pool.python_group;
        cfg_group  = (vh && vh->python.node_count > 0) ? &vh->python : &config.python;
    }

    if (cfg_group->node_count <= 0) {
        return -1;
    }

    int idx;
    if (strcmp(cfg_group->lb_strategy, "ip_hash") == 0) {
        idx = hash_ip(req->client_ip) % cfg_group->node_count;
    } else {
        idx = atomic_fetch_add(&live_group->next_idx, 1) % cfg_group->node_count;
    }

    int fpm_sock = fcgi_pool_conn_acquire(cfg_group->ips[idx], cfg_group->ports[idx]);
    if (fpm_sock < 0) {
        return -1;
    }

    // Set non blocking
    if (fcgi_set_socket_nonblocking(fpm_sock) == -1) {
        // Tutup socket atau kembalikan ke pool jika gagal set non-blocking
        close(fpm_sock); 
        return -1;
    }

    return fpm_sock;
}

// Menghancurkan Sesi dan Mengembalikan/Membuang Koneksi FPM
void fcgi_session_destroy(FCGISession *session) {
    if (!session) return;

    if (session->fpm_sock != -1) {
        if (session->state == FCGI_SES_STATE_ERROR) {
            // Socket rusak/poisoned, tutup permanen agar tidak mencemari pool
            close(session->fpm_sock);
        } else {
            // Normal/Sukses, kembalikan koneksi ke pool
            fcgi_pool_conn_release(session->fpm_sock);
        }
        session->fpm_sock = -1;
    }

    free(session);
}

// Eksekusi Langkah State Machine (FSM Step) per I/O Event
int fcgi_session_http1_step(FCGISession *session, uint32_t revents) {
    if (!session) {
        //fprintf(stderr, "[DEBUG-FCGI] ERROR: session NULL\n");
        return FCGI_SES_STATUS_ERROR;
    }

    //fprintf(stderr, "[DEBUG-FCGI] Step masuk: state=%d, revents=0x%X, content_length=%zu, stdin_sent=%zu\n", 
    //        session->state, revents, session->content_length, session->stdin_sent);

    switch (session->state) {
        case FCGI_SES_STATE_INIT:
        case FCGI_SES_STATE_SENDING_PARAMS: {
            if (revents & POLLOUT) {
                size_t remaining = session->g_ptr - session->g_sent;
                //fprintf(stderr, "[DEBUG-FCGI] SENDING_PARAMS: remaining=%zu bytes\n", remaining);
                
                ssize_t n = send(session->fpm_sock, session->gather_buf + session->g_sent, remaining, MSG_NOSIGNAL);

                if (n > 0) {
                    session->g_sent += n;
                    //fprintf(stderr, "[DEBUG-FCGI] SENDING_PARAMS: terkirim %zd bytes, total g_sent=%d/%d\n", 
                    //        n, session->g_sent, session->g_ptr);
                    
                    if (session->g_sent >= session->g_ptr) {
                        session->state = (session->content_length > 0 && session->post_data) ? 
                                         FCGI_SES_STATE_SENDING_STDIN : FCGI_SES_STATE_RECEIVING;
                        //fprintf(stderr, "[DEBUG-FCGI] Params selesai. Pindah state ke: %d\n", session->state);
                    }
                } else if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        fprintf(stderr, "[DEBUG-FCGI] SENDING_PARAMS: EAGAIN/EWOULDBLOCK\n");
                        return FCGI_SES_STATUS_CONTINUE;
                    }
                    //fprintf(stderr, "[DEBUG-FCGI] ERROR send params: %s\n", strerror(errno));
                    session->state = FCGI_SES_STATE_ERROR;
                    return FCGI_SES_STATUS_ERROR;
                }
            } /*else {
                fprintf(stderr, "[DEBUG-FCGI] SENDING_PARAMS: menolak/belum siap POLLOUT (revents=0x%X)\n", revents);
            }*/
            break;
        }

        case FCGI_SES_STATE_SENDING_STDIN: {
            if (revents & POLLOUT) {
                size_t remaining = session->content_length - session->stdin_sent;
                size_t chunk_size = (remaining > 32768) ? 32768 : remaining;

                //fprintf(stderr, "[DEBUG-FCGI] SENDING_STDIN: remaining=%zu, chunk_size=%zu\n", remaining, chunk_size);

                if (chunk_size > 0) {
                    int pad = (8 - (chunk_size % 8)) % 8;
                    unsigned char record_buf[sizeof(HalmosFCGI_Header) + 32768 + 8];
                    int r_ptr = 0;

                    HalmosFCGI_Header *h = (HalmosFCGI_Header*)record_buf;
                    h->version = FCGI_VERSION_1;
                    h->type = FCGI_STDIN;
                    h->requestIdB1 = (session->request_id >> 8) & 0xFF;
                    h->requestIdB0 = session->request_id & 0xFF;
                    h->contentLengthB1 = (chunk_size >> 8) & 0xFF;
                    h->contentLengthB0 = chunk_size & 0xFF;
                    h->paddingLength = (unsigned char)pad;
                    h->reserved = 0;
                    r_ptr += sizeof(HalmosFCGI_Header);

                    memcpy(record_buf + r_ptr, (char*)session->post_data + session->stdin_sent, chunk_size);
                    r_ptr += chunk_size;

                    if (pad > 0) {
                        memset(record_buf + r_ptr, 0, pad);
                        r_ptr += pad;
                    }

                    ssize_t n = send(session->fpm_sock, record_buf, r_ptr, MSG_NOSIGNAL);
                    if (n > 0) {
                        session->stdin_sent += chunk_size;
                        //fprintf(stderr, "[DEBUG-FCGI] STDIN terkirim %zd bytes, total stdin_sent=%zu/%zu\n", 
                        //        n, session->stdin_sent, session->content_length);
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        //fprintf(stderr, "[DEBUG-FCGI] ERROR send stdin: %s\n", strerror(errno));
                        session->state = FCGI_SES_STATE_ERROR;
                        return FCGI_SES_STATUS_ERROR;
                    }
                }

                // Cek jika seluruh STDIN sudah terkirim, kirim paket STDIN kosong (EOF)
                if (session->stdin_sent >= session->content_length) {
                    //fprintf(stderr, "[DEBUG-FCGI] STDIN selesai seluruhnya. Mengirim EOF STDIN kosong...\n");
                    HalmosFCGI_Header empty_h = {0};
                    empty_h.version = FCGI_VERSION_1;
                    empty_h.type = FCGI_STDIN;
                    empty_h.requestIdB1 = (session->request_id >> 8) & 0xFF;
                    empty_h.requestIdB0 = session->request_id & 0xFF;

                    send(session->fpm_sock, &empty_h, sizeof(empty_h), MSG_NOSIGNAL);
                    session->state = FCGI_SES_STATE_RECEIVING;
                    //fprintf(stderr, "[DEBUG-FCGI] Pindah state ke FCGI_SES_STATE_RECEIVING\n");
                }
            } /*else {
                fprintf(stderr, "[DEBUG-FCGI] SENDING_STDIN: belum siap POLLOUT (revents=0x%X)\n", revents);
            }*/
            break;
        }

        case FCGI_SES_STATE_RECEIVING: {
            if (revents & POLLIN) {
                //fprintf(stderr, "[DEBUG-FCGI] RECEIVING: Siap membaca respons dari PHP-FPM\n");
                int ret = fcgi_io_splice_response(session->fpm_sock, session->client_sock, session->req);
                
                if (ret == 0) {
                    //fprintf(stderr, "[DEBUG-FCGI] RECEIVING: Selesai membaca respons (COMPLETED)\n");
                    session->state = FCGI_SES_STATE_FINISHED;
                    return FCGI_SES_STATUS_COMPLETED;
                } else {
                    //fprintf(stderr, "[DEBUG-FCGI] ERROR: fcgi_io_splice_response gagal (ret=%d)\n", ret);
                    session->state = FCGI_SES_STATE_ERROR;
                    return FCGI_SES_STATUS_ERROR;
                }
            } /*else {
                fprintf(stderr, "[DEBUG-FCGI] RECEIVING: Belum ada data masuk (revents=0x%X)\n", revents);
            }*/
            break;
        }

        case FCGI_SES_STATE_FINISHED:
            //fprintf(stderr, "[DEBUG-FCGI] State FINISHED\n");
            return FCGI_SES_STATUS_COMPLETED;

        case FCGI_SES_STATE_ERROR:
        default:
            //fprintf(stderr, "[DEBUG-FCGI] State ERROR/UNKNOWN\n");
            return FCGI_SES_STATUS_ERROR;
    }

    return FCGI_SES_STATUS_CONTINUE;
}

int fcgi_session_http2_step(HTTP2Session *session, HTTP2Stream *stream, uint32_t revents) {
    if (!stream || !stream->is_fcgi_active) {
        //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Invalid stream or not active\n", stream ? stream->stream_id : 0);
        return FCGI_SES_STATUS_ERROR;
    }

    RequestHeader *req = &stream->http1_compat;
    //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Step called, current fcgi_state=%d, revents=0x%X\n", 
    //        stream->stream_id, stream->fcgi_state, revents);

    switch (stream->fcgi_state) {
        case 0: { // STATE: Inisialisasi & Meracik Begin Request & Params
            stream->fcgi_g_ptr = 0;
            stream->fcgi_g_sent = 0;

            // A. Buat Header Begin Request FastCGI
            HalmosFCGI_Header *h = (HalmosFCGI_Header*)&stream->fcgi_gather_buf[stream->fcgi_g_ptr];
            memset(h, 0, sizeof(HalmosFCGI_Header));
            h->version = FCGI_VERSION_1;
            h->type = FCGI_BEGIN_REQUEST;
            h->requestIdB0 = stream->stream_id & 0xFF;
            h->requestIdB1 = (stream->stream_id >> 8) & 0xFF;
            h->contentLengthB0 = 8;
            stream->fcgi_g_ptr += sizeof(HalmosFCGI_Header);
            
            stream->fcgi_gather_buf[(stream->fcgi_g_ptr)++] = 0;             // Role Responder B1
            stream->fcgi_gather_buf[(stream->fcgi_g_ptr)++] = FCGI_RESPONDER;// Role Responder B0
            stream->fcgi_gather_buf[(stream->fcgi_g_ptr)++] = FCGI_KEEP_CONN;// Keep Conn Flag
            memset(&stream->fcgi_gather_buf[stream->fcgi_g_ptr], 0, 5); 
            stream->fcgi_g_ptr += 5;

            // Gunakan variabel int sementara untuk menghindari warning incompatible pointer type
            int temp_g_ptr = (int)stream->fcgi_g_ptr;
            fcgi_proto_build_params(req, stream->fpm_fd, req->content_length, stream->fcgi_gather_buf, &temp_g_ptr, stream->stream_id);
            stream->fcgi_g_ptr = (size_t)temp_g_ptr;

            // Pindah ke state 1
            stream->fcgi_state = 1;
            
            // fallthrough agar langsung mengeksekusi case 1 di siklus yang sama
            __attribute__((fallthrough));
        }
        case 1: { // STATE: Mengirim Begin Request & Params
            if (revents & POLLOUT) {
                size_t remaining = stream->fcgi_g_ptr - stream->fcgi_g_sent;
                //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Sending params/begin, remaining=%zu, fpm_fd=%d\n", 
                //        stream->stream_id, remaining, stream->fpm_fd);

                ssize_t n = send(stream->fpm_fd, stream->fcgi_gather_buf + stream->fcgi_g_sent, remaining, MSG_NOSIGNAL);
                if (n > 0) {
                    stream->fcgi_g_sent += n;
                    //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Sent %zd bytes, total sent=%zu/%zu\n", 
                    //        stream->stream_id, n, stream->fcgi_g_sent, stream->fcgi_g_ptr);
                    
                    if (stream->fcgi_g_sent >= stream->fcgi_g_ptr) {
                        stream->fcgi_state = (req->content_length > 0 && req->body_data) ? 2 : 3;
                        //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Params fully sent. Moving to state %d\n", 
                        //        stream->stream_id, stream->fcgi_state);
                    }
                } else if (n < 0) {
                    //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Send error n=%zd, errno=%d (%s)\n", 
                    //        stream->stream_id, n, errno, strerror(errno));
                    if (errno == EAGAIN || errno == EWOULDBLOCK) return FCGI_SES_STATUS_CONTINUE;
                    stream->fcgi_state = 5; 
                    return FCGI_SES_STATUS_ERROR;
                }
            }
            break;
        }

        case 2: { // STATE: Mengirim POST Body / STDIN ke PHP-FPM
            if (revents & POLLOUT) {
                size_t content_len = (size_t)(req->content_length > 0 ? req->content_length : 0);

                if (stream->fcgi_stdin_sent < content_len) {
                    size_t remaining_body = content_len - stream->fcgi_stdin_sent;
                    size_t chunk_size = remaining_body > 8192 ? 8192 : remaining_body;

                    // Meracik Record FastCGI STDIN (Type 5)
                    unsigned char stdin_header[8];
                    stdin_header[0] = FCGI_VERSION_1;
                    stdin_header[1] = FCGI_STDIN; // Type 5
                    stdin_header[2] = (stream->stream_id >> 8) & 0xFF;
                    stdin_header[3] = stream->stream_id & 0xFF;
                    stdin_header[4] = (chunk_size >> 8) & 0xFF;
                    stdin_header[5] = chunk_size & 0xFF;
                    stdin_header[6] = 0; // Padding length
                    stdin_header[7] = 0; // Reserved

                    // Kirim Header STDIN & Payload Body Data
                    ssize_t nw1 = send(stream->fpm_fd, stdin_header, 8, MSG_NOSIGNAL);
                    ssize_t nw2 = send(stream->fpm_fd, req->body_data + stream->fcgi_stdin_sent, chunk_size, MSG_NOSIGNAL);

                    if (nw1 > 0 && nw2 > 0) {
                        stream->fcgi_stdin_sent += chunk_size;
                        //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Sent POST chunk %zu/%zu bytes\n", 
                        //        stream->stream_id, stream->fcgi_stdin_sent, content_len);
                    } else if (nw1 < 0 || nw2 < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) return FCGI_SES_STATUS_CONTINUE;
                        stream->fcgi_state = 5;
                        return FCGI_SES_STATUS_ERROR;
                    }
                }

                // Jika seluruh POST body sudah terkirim, kirimkan STDIN kosong sebagai EOF
                if (stream->fcgi_stdin_sent >= content_len) {
                    unsigned char fcgi_stdin_eof[8] = {
                        FCGI_VERSION_1, FCGI_STDIN,
                        (stream->stream_id >> 8) & 0xFF, stream->stream_id & 0xFF,
                        0, 0, // Content length = 0
                        0, 0  // Padding, Reserved
                    };
                    send(stream->fpm_fd, fcgi_stdin_eof, 8, MSG_NOSIGNAL);

                    // Pindah ke state 3 untuk mulai membaca balasan dari PHP-FPM
                    stream->fcgi_state = 3;
                    //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: POST body fully sent. Moving to state 3\n", stream->stream_id);
                }
            }
            break;
        }
        
        case 3: { // STATE: Menerima Respons dari PHP-FPM
            //fprintf(stderr, "[H2-FCGI-TRACE] Stream %u: Entered state 3, revents=0x%X\n", stream->stream_id, revents);

            if (revents & POLLIN) {
                unsigned char fpm_chunk[8192];
                ssize_t n = recv(stream->fpm_fd, fpm_chunk, sizeof(fpm_chunk), 0);
                
                //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: recv() returned n=%zd (errno=%d)\n", stream->stream_id, n, n < 0 ? errno : 0);

                if (n > 0) {
                    //fprintf(stderr, "[H2-FCGI-DEBUG] === START PARSING CHUNK: n=%zd bytes ===\n", n);
                    size_t offset = 0;
                    
                    while (offset + 8 <= (size_t)n) {
                        unsigned char *header_ptr = fpm_chunk + offset;
                        //unsigned char version = header_ptr[0];
                        unsigned char type = header_ptr[1];
                        //uint16_t requestId = (uint16_t)(((header_ptr[2] & 0xFF) << 8) | (header_ptr[3] & 0xFF));
                        uint16_t content_length = (uint16_t)(((header_ptr[4] & 0xFF) << 8) | (header_ptr[5] & 0xFF));
                        unsigned char padding_length = header_ptr[6];
                        //unsigned char reserved = header_ptr[7];

                        //fprintf(stderr, "[H2-FCGI-DEBUG]   [RECORD] offset=%zu | ver=%u, type=%u, reqId=%u, contentLen=%u, padding=%u, res=%u\n",
                        //        offset, version, type, requestId, content_length, padding_length, reserved);

                        //size_t header_offset = offset;
                        offset += 8; // Lewati header

                        if (type == 6) { // FCGI_STDOUT
                            ssize_t available_in_chunk = (ssize_t)n - (ssize_t)offset;
                            if (available_in_chunk < 0) available_in_chunk = 0;

                            //fprintf(stderr, "[H2-FCGI-DEBUG]   [FCGI_STDOUT] content_length=%u, available_in_chunk=%zd\n", 
                            //        content_length, available_in_chunk);

                            /*if (available_in_chunk > 0) {
                                fprintf(stderr, "[H2-FCGI-DEBUG]   [RAW BYTES] First few bytes: '%.*s'\n", 
                                        (int)(available_in_chunk < 16 ? available_in_chunk : 16), fpm_chunk + offset);
                            }*/

                            size_t bytes_to_copy = (available_in_chunk < (ssize_t)content_length) ? (size_t)available_in_chunk : (size_t)content_length;
                            
                            //size_t space_left = sizeof(stream->fcgi_header_buffer) - stream->fcgi_header_bytes_read - 1;
                            size_t space_left = GATHER_BUF_SIZE - stream->fcgi_header_bytes_read - 1;
                            //fprintf(stderr, "[H2-FCGI-DEBUG]   [COPY] bytes_to_copy=%zu, space_left_in_buffer=%zu\n", 
                            //        bytes_to_copy, space_left);

                            if (bytes_to_copy > space_left) {
                                bytes_to_copy = space_left;
                            }

                            if (bytes_to_copy > 0) {
                                memcpy(stream->fcgi_header_buffer + stream->fcgi_header_bytes_read, fpm_chunk + offset, bytes_to_copy);
                                stream->fcgi_header_bytes_read += bytes_to_copy;
                                stream->fcgi_header_buffer[stream->fcgi_header_bytes_read] = '\0';
                            }

                            offset += content_length; 
                        } else if (type == 3) { // FCGI_END_REQUEST
                            //fprintf(stderr, "[H2-FCGI-DEBUG]   [FCGI_END_REQUEST] Encountered at offset=%zu\n", header_offset);
                            break;
                        } else {
                            //fprintf(stderr, "[H2-FCGI-DEBUG]   [OTHER TYPE] Skipping type=%u with content_length=%u\n", type, content_length);
                            offset += content_length;
                        }

                        // Majukan offset berdasarkan padding length dari record FastCGI
                        offset += padding_length;
                    }

                    //fprintf(stderr, "[H2-FCGI-DEBUG] === END PARSING CHUNK. Total buffered so far: %zu bytes ===\n", stream->fcgi_header_bytes_read);
                    //fprintf(stderr, "[H2-FCGI-DUMP] Buffer content:\n---\n%s\n---\n", stream->fcgi_header_buffer);

                    // Cek delimiter
                    char *delim = strstr(stream->fcgi_header_buffer, "\r\n\r\n");
                    if (delim) {
                        *delim = '\0';
                        char *raw_headers = stream->fcgi_header_buffer;
                        char *body_data = delim + 4;
                        size_t body_len = stream->fcgi_header_bytes_read - (body_data - stream->fcgi_header_buffer);

                        //fprintf(stderr, "[H2-FCGI-DEBUG] Delimiter found! Sending headers and body (%zu bytes)\n", body_len);

                        if (!stream->fcgi_header_sent) {
                            http2_response_send_complex_header(session, stream, raw_headers, 0x04);
                            stream->fcgi_header_sent = true;
                        }

                        if (body_len > 0) {
                            http2_response_send_data(session, stream, body_data, body_len, true);
                        } else {
                            http2_response_send_data(session, stream, "", 0, true);
                        }

                        stream->fcgi_state = 4; 
                        return FCGI_SES_STATUS_COMPLETED;
                    } else {
                        return FCGI_SES_STATUS_CONTINUE;
                    }
                } else if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return FCGI_SES_STATUS_CONTINUE;
                    } else {
                        //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: Recv error errno=%d (%s)\n", stream->stream_id, errno, strerror(errno));
                        return FCGI_SES_STATUS_ERROR;
                    }
                } else if (n == 0) {
                    //fprintf(stderr, "[H2-FCGI-DEBUG] Stream %u: FPM closed connection (EOF)\n", stream->stream_id);
                    return FCGI_SES_STATUS_ERROR;
                }
            }
            break;
        }
        default:
            break;
    }

    return FCGI_SES_STATUS_CONTINUE;
}

// Helper untuk membuat socket menjadi non-blocking agar ramah event-loop (epoll/poll)
int fcgi_set_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}