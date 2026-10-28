#include "halmos_fcgi_fsm.h"
#include "halmos_global.h"
#include "halmos_core_conn_table.h"
#include "halmos_http2_core.h"
#include "halmos_fcgi_queue.h"
#include "halmos_fcgi_event_loop.h"
#include "halmos_fcgi_proto.h"
#include "halmos_log.h"
#include "halmos_http_utils.h"
#include "halmos_sec_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// ==========================================
// 1. FSM STEP KHUSUS HTTP/1.1 (Mengikuti Pola Bersih HTTP/2)
// ==========================================
bool fcgi_fsm_step_http1(FCGI_Session *session) {
    if (!session) return false;

    // --- GUARD MUTLAK ANTI-CRASH & BAD DESCRIPTOR ---
    pthread_mutex_lock(&session->lock);
    if (session->fpm_fd < 0 || session->fpm_fd == -99) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    pthread_mutex_unlock(&session->lock);

    fprintf(stderr, "[DEBUG FSM H1] === START STEP == | session=%p, fpm_fd=%d\n", (void*)session, session ? session->fpm_fd : -99);
    
    if (!session || session->fpm_fd == -1 || session->fpm_fd == -99) {
        fprintf(stderr, "[DEBUG FSM H1] ABORT: session is NULL, fpm_fd == -1, or session already destroyed (-99)\n");
        return false;
    }

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    
    fprintf(stderr, "[DEBUG FSM H1] recv header n_head=%zd, fpm_fd=%d\n", n_head, session->fpm_fd);

    if (n_head <= 0) {
        if (n_head < 0) {
            fprintf(stderr, "[DEBUG FSM H1] ERROR recv header: errno=%d (%s)\n", errno, strerror(errno));
        } else {
            fprintf(stderr, "[DEBUG FSM H1] FPM EOF detected (n_head == 0)\n");
        }
        
        session->is_fcgi_active = false;
        
        // Hapus dari epoll dengan aman saat koneksi terputus/selesai
        if (session->fpm_fd != -1 && session->fpm_fd != -99) {
            fcgi_event_loop_del(session->fpm_fd);
        }
        
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    
    if (n_head < 8) {
        fprintf(stderr, "[DEBUG FSM H1] WARNING: Incomplete header received (n_head < 8). Waiting for more data.\n");
        pthread_mutex_unlock(&session->lock);
        
        // CATATAN: Jangan panggil fcgi_event_loop_add di sini agar tidak terjadi race condition! 
        // Biarkan poller upstream menangani event masuk berikutnya secara bersih.
        return true;
    }

    FCGI_Header *h = (FCGI_Header *)h_buf;
    int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
    int plen = h->paddingLength;

    fprintf(stderr, "[DEBUG FSM H1] FastCGI Header parsed -> type=%d, content_length=%d, padding_length=%d\n", h->type, clen, plen);

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1);
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) {
                        fprintf(stderr, "[DEBUG FSM H1] ERROR reading STDOUT payload chunk: nr=%zd, errno=%d\n", nr, errno);
                        break;
                    }
                    read_bytes += nr;
                }
                payload[read_bytes] = '\0';
                fprintf(stderr, "[DEBUG FSM H1] Successfully read STDOUT payload bytes = %d\n", read_bytes);

                // --- BUFFERING KE HTTP/1 SESSION ---
                int payload_offset = 0;

                if (!session->fcgi_header_parsed) {
                    size_t space_left = FCGI_HEADER_BUF_SIZE - session->fcgi_h_ptr - 1;
                    size_t to_copy = (size_t)(read_bytes - payload_offset) < space_left ? (size_t)(read_bytes - payload_offset) : space_left;

                    if (to_copy > 0) {
                        memcpy(session->fcgi_header_buf + session->fcgi_h_ptr, payload + payload_offset, to_copy);
                        session->fcgi_h_ptr += to_copy;
                        session->fcgi_header_buf[session->fcgi_h_ptr] = '\0';
                        payload_offset += to_copy;
                    }

                    char *sep = strstr((char *)session->fcgi_header_buf, "\r\n\r\n");
                    if (!sep) {
                        sep = strstr((char *)session->fcgi_header_buf, "\n\n");
                    }

                    if (sep) {
                        session->fcgi_header_parsed = true;
                        size_t header_len_actual = (size_t)(sep - (char *)session->fcgi_header_buf) + (sep[0] == '\r' ? 4 : 2);
                        fprintf(stderr, "[DEBUG FSM H1] HTTP headers fully parsed from FPM! header_len_actual=%zu\n", header_len_actual);
                        
                        if (session->fcgi_h_ptr > header_len_actual) {
                            size_t spill_len = session->fcgi_h_ptr - header_len_actual;
                            size_t body_space_left = GATHER_BUF_SIZE - session->fcgi_g_ptr;
                            
                            if (spill_len <= body_space_left) {
                                memcpy(session->fcgi_gather_buf + session->fcgi_g_ptr, session->fcgi_header_buf + header_len_actual, spill_len);
                                session->fcgi_g_ptr += spill_len;
                            }
                            session->fcgi_h_ptr = header_len_actual;
                            session->fcgi_header_buf[header_len_actual] = '\0';
                        }

                        if (payload_offset < read_bytes) {
                            int body_chunk = read_bytes - payload_offset;
                            size_t body_space_left = GATHER_BUF_SIZE - session->fcgi_g_ptr;

                            if ((size_t)body_chunk <= body_space_left) {
                                memcpy(session->fcgi_gather_buf + session->fcgi_g_ptr, payload + payload_offset, body_chunk);
                                session->fcgi_g_ptr += body_chunk;
                            }
                        }
                    }
                } else {
                    int body_chunk = read_bytes - payload_offset;
                    size_t space_left = GATHER_BUF_SIZE - session->fcgi_g_ptr;

                    if (body_chunk > 0 && (size_t)body_chunk <= space_left) {
                        memcpy(session->fcgi_gather_buf + session->fcgi_g_ptr, payload + payload_offset, body_chunk);
                        session->fcgi_g_ptr += body_chunk;
                    }
                }

                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        fprintf(stderr, "[DEBUG FSM H1] FCGI_END_REQUEST reached | session=%p, pushing TASK_PROCESS_READ\n", (void*)session);
        if (!session->fcgi_header_parsed && session->fcgi_h_ptr > 0) {
            session->fcgi_header_parsed = true;
        }
        session->is_fcgi_active = false;
        
        if (session->fpm_fd != -1 && session->fpm_fd != -99) {
            fcgi_event_loop_del(session->fpm_fd);
        }

        pthread_mutex_unlock(&session->lock);
        return false; 
    }

    if (plen > 0) {
        char junk[256];
        int pad_read = 0;
        while (pad_read < plen) {
            int chunk = (plen - pad_read > (int)sizeof(junk)) ? (int)sizeof(junk) : (plen - pad_read);
            ssize_t nr = recv(session->fpm_fd, junk, chunk, 0);
            if (nr <= 0) break;
            pad_read += nr;
        }
        fprintf(stderr, "[DEBUG FSM H1] Ignored padding bytes: %d\n", pad_read);
    }

    pthread_mutex_unlock(&session->lock);

    // === PERBAIKAN: RE-ARM EPOLL AGAR CHUNK BERIKUTNYA / END_REQUEST TERDETEKSI ===
    if (session->fpm_fd != -1 && session->fpm_fd != -99) {
        fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
        fprintf(stderr, "[DEBUG FSM H1] Re-armed fpm_fd=%d to epoll for next chunks.\n", session->fpm_fd);
    }

    fprintf(stderr, "[DEBUG FSM H1] === END STEP SUCCESS (waiting next event from poller) ===\n");

    return true; 
}
// ==========================================
// 2. FSM STEP KHUSUS HTTP/2 (Kerangka / Placeholder Awal)
// ==========================================
bool fcgi_fsm_step_http2(FCGI_Session *session) {
    
    if (!session) return false;

    // --- GUARD MUTLAK ANTI-CRASH & BAD DESCRIPTOR ---
    pthread_mutex_lock(&session->lock);
    if (session->fpm_fd < 0 || session->fpm_fd == -99) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    pthread_mutex_unlock(&session->lock);

    pthread_mutex_lock(&session->lock);

    unsigned char h_buf[8];
    ssize_t n_head = recv(session->fpm_fd, h_buf, 8, 0);
    if (n_head <= 0) {
        pthread_mutex_unlock(&session->lock);
        return false; 
    }
    
    if (n_head < 8) {
        pthread_mutex_unlock(&session->lock);
        // WAJIB RE-ARM KE EPOLL AGAR SISA BYTES BISA DIBACA BERIKUTNYA
        if (session->fpm_fd != -1) {
            fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
        }
        return true;
    }

    FCGI_Header *h = (FCGI_Header *)h_buf;
    int clen = (h->contentLengthB1 << 8) | h->contentLengthB0;
    int plen = h->paddingLength;
    
    // AMBIL LANGSUNG STREAM DARI SESSION H2 (Pastikan session->h2_session dan session->h2_stream sinkron)
    HTTP2Stream *stream = session->h2_stream;

    if (h->type == FCGI_STDOUT) {
        if (clen > 0) {
            char *payload = malloc(clen + 1); // Tambah 1 untuk null terminator
            if (payload) {
                int read_bytes = 0;
                while (read_bytes < clen) {
                    ssize_t nr = recv(session->fpm_fd, payload + read_bytes, clen - read_bytes, 0);
                    if (nr <= 0) break;
                    read_bytes += nr;
                }
                payload[read_bytes] = '\0'; // Aman dicetak sebagai string

                // --- TAMBAHAN DEBUG MENTAH FPM ---
                //fprintf(stderr, "[FCGI-RAW] Received %d bytes from FPM:\n%.*s\n--- END RAW ---\n", 
                //        read_bytes, (int)read_bytes, payload);

                if (stream) {
                    int payload_offset = 0;

                    if (!stream->fcgi_header_parsed) {
                        size_t space_left = FCGI_HEADER_BUF_SIZE - stream->fcgi_h_ptr - 1;
                        size_t to_copy = (size_t)(read_bytes - payload_offset) < space_left ? (size_t)(read_bytes - payload_offset) : space_left;

                        if (to_copy > 0) {
                            memcpy(stream->fcgi_header_buf + stream->fcgi_h_ptr, payload + payload_offset, to_copy);
                            stream->fcgi_h_ptr += to_copy;
                            stream->fcgi_header_buf[stream->fcgi_h_ptr] = '\0';
                            payload_offset += to_copy;
                        }

                        char *sep = strstr((char *)stream->fcgi_header_buf, "\r\n\r\n");
                        if (!sep) {
                            sep = strstr((char *)stream->fcgi_header_buf, "\n\n"); // Fallback deteksi newline ganda biasa
                        }

                        if (sep) {
                            stream->fcgi_header_parsed = true;
                            
                            // Hitung posisi awal body yang sebenarnya
                            size_t header_len_actual = (size_t)(sep - stream->fcgi_header_buf) + (sep[0] == '\r' ? 4 : 2);
                            
                            // Jika ada sisa byte di dalam buffer header yang masuk wilayah body
                            if (stream->fcgi_h_ptr > header_len_actual) {
                                size_t spill_len = stream->fcgi_h_ptr - header_len_actual;
                                size_t body_space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;
                                
                                if (spill_len <= body_space_left) {
                                    memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, stream->fcgi_header_buf + header_len_actual, spill_len);
                                    stream->fcgi_g_ptr += spill_len;
                                }
                                // Koreksi ulang ukuran buffer header murni
                                stream->fcgi_h_ptr = header_len_actual;
                                stream->fcgi_header_buf[header_len_actual] = '\0';
                            }

                            // Jika ada sisa payload setelah pemisah yang belum masuk
                            if (payload_offset < read_bytes) {
                                int body_chunk = read_bytes - payload_offset;
                                size_t body_space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;

                                if ((size_t)body_chunk <= body_space_left) {
                                    memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, body_chunk);
                                    stream->fcgi_g_ptr += body_chunk;
                                }
                            }
                        }
                    } else {
                        int body_chunk = read_bytes - payload_offset;
                        size_t space_left = GATHER_BUF_SIZE - stream->fcgi_g_ptr;

                        if (body_chunk > 0 && (size_t)body_chunk <= space_left) {
                            memcpy(stream->fcgi_gather_buf + stream->fcgi_g_ptr, payload + payload_offset, body_chunk);
                            stream->fcgi_g_ptr += body_chunk;
                        }
                    }
                }
                free(payload);
            }
        }
    } else if (h->type == FCGI_END_REQUEST) {
        if (stream) {
            if (!stream->fcgi_header_parsed && stream->fcgi_h_ptr > 0) {
                stream->fcgi_header_parsed = true;
            }
            stream->is_fcgi_active = false;
            
            //fprintf(stderr, "[FCGI-FSM] Stream %u Done | Header: %zu bytes | Body: %zu bytes\n", 
            //        stream->stream_id, stream->fcgi_h_ptr, stream->fcgi_g_ptr);
        }
        pthread_mutex_unlock(&session->lock);
        return false; 
    }

    if (plen > 0) {
        char junk[256];
        int pad_read = 0;
        while (pad_read < plen) {
            int chunk = (plen - pad_read > (int)sizeof(junk)) ? (int)sizeof(junk) : (plen - pad_read);
            ssize_t nr = recv(session->fpm_fd, junk, chunk, 0);
            if (nr <= 0) break;
            pad_read += nr;
        }
    }

    pthread_mutex_unlock(&session->lock);

    if (session->fpm_fd != -1) {
        fcgi_event_loop_add(session->fpm_fd, session, EPOLLIN);
    }

    return true;
}

