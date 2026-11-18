#include "halmos_core_quic_event_loop.h"
#include "halmos_transport_udp_server.h"
#include "halmos_core_quic_conn_table.h"
#include "halmos_sec_quic_tls.h"
#include "halmos_sec_quic_crypto.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_admission.h"
#include "halmos_core_conn_table.h"
#include "halmos_core_queue.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

/* Struktur State Poller QUIC (Mirip FCGI_AsyncEventLoop) */
typedef struct {
    int epoll_fd;
    int sock_server;
    pthread_t event_thread;
    atomic_bool running;
} QuicAsyncEventLoop;

extern QuicConnTable quic_conn_table;

static QuicAsyncEventLoop quic_poller = { .epoll_fd = -1, .sock_server = -1, .event_thread = 0, .running = false };
static struct epoll_event *g_quic_events = NULL;

/* Deklarasi fungsi worker thread */
static void* quic_event_loop_run_thread(void *arg);

// Fungsi helper terpusat untuk mencetak hex dump outbound
void print_outbound_hex_dump(const char *label, const unsigned char *packet_out, size_t pkt_pos, size_t pn_offset) {
    fprintf(stderr, "========== [QUIC OUTBOUND HANDSHAKE DUMP: %s] ==========\n", label);
    fprintf(stderr, "Handshake Packet Len: %zu\n", pkt_pos);
    fprintf(stderr, "First Byte (Protected): 0x%02x\n", packet_out[0]);
    fprintf(stderr, "Packet Number Offset   : %zu\n", pn_offset);
    fprintf(stderr, "Encrypted Payload+Tag  : ");
    for (size_t dbg = pn_offset + 1; dbg < pkt_pos && dbg < pn_offset + 32; dbg++) {
        fprintf(stderr, "%02x", packet_out[dbg]);
    }
    fprintf(stderr, "...\n====================================================\n");
}

bool core_quic_event_loop_start(void) {
    if (core_quic_conn_table_init(&quic_conn_table) != 0) {
        write_log("[QUIC ERROR] Failed to initialize QUIC connection table.");
        return false;
    }

    quic_poller.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (quic_poller.epoll_fd == -1) {
        write_log_error_code(ERR_CORE_EPOLL_CREATE, strerror(errno));
        return false;
    }

    /* Alokasi dinamis event batch berdasarkan adaptive hardware */
    g_quic_events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * adaptive_hw_aware.event_batch_size);
    if (!g_quic_events) {
        write_log_error_code(ERR_CORE_EPOLL_MEM);
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    /* Buat server UDP menggunakan modul Anda */
    quic_poller.sock_server = udp_create_server(config.server_name, config.server_port);
    if (quic_poller.sock_server < 0) {
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    /* Daftarkan socket UDP ke epoll QUIC */
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = quic_poller.sock_server;

    if (epoll_ctl(quic_poller.epoll_fd, EPOLL_CTL_ADD, quic_poller.sock_server, &ev) < 0) {
        write_log_error_code(ERR_CORE_EPOLL_ADD_SOCK, strerror(errno));
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    atomic_store(&quic_poller.running, true);

    /* Luncurkan thread mandiri untuk QUIC poller */
    if (pthread_create(&quic_poller.event_thread, NULL, quic_event_loop_run_thread, NULL) != 0) {
        atomic_store(&quic_poller.running, false);
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
        free(g_quic_events);
        g_quic_events = NULL;
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
        return false;
    }

    write_log("[QUIC CORE] QUIC Server listening on UDP %s:%d (Thread-based)", config.server_name, config.server_port);
    return true;
}

void core_quic_event_loop_stop(void) {
    atomic_store(&quic_poller.running, false);

    /* 1. Tunggu thread poller selesai TERLEBIH DAHULU */
    if (quic_poller.event_thread) {
        pthread_join(quic_poller.event_thread, NULL);
        quic_poller.event_thread = 0;
    }

    /* 2. Tutup socket server */
    if (quic_poller.sock_server != -1) {
        close(quic_poller.sock_server);
        quic_poller.sock_server = -1;
    }

    /* 3. Tutup epoll_fd setelah thread benar-benar mati */
    if (quic_poller.epoll_fd != -1) {
        close(quic_poller.epoll_fd);
        quic_poller.epoll_fd = -1;
    }

    /* 4. Bebaskan memori batch events */
    if (g_quic_events) {
        free(g_quic_events);
        g_quic_events = NULL;
    }

    core_quic_conn_table_destroy(&quic_conn_table);
    write_log("[QUIC CORE] QUIC Server stopped and cleaned up safely.");
}

// Helper 1: Parsing header QUIC Initial untuk mendapatkan ukuran dan offset packet number
static int quic_parse_packet_header(const unsigned char *buffer, size_t nbytes, 
                                     size_t *out_pn_offset, size_t *out_real_packet_len, 
                                     const unsigned char **out_dcid_ptr, uint8_t *out_dcid_len,
                                     const unsigned char **out_scid_ptr, uint8_t *out_scid_len,
                                     int *out_pkt_type) {
    if (nbytes <= 6) return 0;

    uint8_t first_byte = buffer[0];
    // Pastikan ini Long Header (bit 0x80 = 1 dan bit 0x40 = 1)
    if ((first_byte & 0xC0) != 0xC0) return 0;

    int pkt_type = (first_byte & 0x30) >> 4; // 0x00 = Initial, 0x02 = Handshake
    if (pkt_type != 0x00 && pkt_type != 0x02) {
        return 0; // Abaikan selain Initial (0) dan Handshake (2)
    }
    *out_pkt_type = pkt_type;

    size_t pos = 1;
    pos += 4; // Version

    // 1. Parse Destination Connection ID (DCID)
    uint8_t pkt_dcid_len = buffer[pos++];
    if (pos + pkt_dcid_len > nbytes) return 0;
    
    *out_dcid_ptr = &buffer[pos];
    *out_dcid_len = pkt_dcid_len;
    pos += pkt_dcid_len;

    // 2. Parse Source Connection ID (SCID)
    if (pos >= nbytes) return 0;
    uint8_t pkt_scid_len = buffer[pos++];
    if (pos + pkt_scid_len > nbytes) return 0;

    *out_scid_ptr = &buffer[pos];
    *out_scid_len = pkt_scid_len;
    pos += pkt_scid_len;

    // 3. Token Length Varint (HANYA ADA DI INITIAL PACKET, TIDAK ADA DI HANDSHAKE!)
    if (pkt_type == 0x00) {
        if (pos >= nbytes) return 0;
        uint8_t token_byte = buffer[pos];
        size_t varint_len = 1;
        uint64_t token_len_val = 0;

        if ((token_byte & 0xC0) == 0x00) {
            varint_len = 1;
            token_len_val = token_byte & 0x3F;
        } else if ((token_byte & 0xC0) == 0x40) {
            varint_len = 2;
            if (pos + 2 > nbytes) return 0;
            token_len_val = ((uint64_t)(token_byte & 0x3F) << 8) | buffer[pos + 1];
        } else if ((token_byte & 0xC0) == 0x80) {
            varint_len = 4;
            if (pos + 4 > nbytes) return 0;
            token_len_val = ((uint64_t)(token_byte & 0x3F) << 24) | ((uint64_t)buffer[pos+1] << 16) | ((uint64_t)buffer[pos+2] << 8) | buffer[pos+3];
        } else {
            varint_len = 8;
            if (pos + 8 > nbytes) return 0;
        }
        pos += varint_len;
        pos += (size_t)token_len_val;
    }

    if (pos >= nbytes) return 0;
    
    // 4. Parse Length Field
    size_t length_field_pos = pos;
    uint8_t len_byte = buffer[pos];
    size_t packet_len_bytes = 1;
    uint64_t actual_packet_length = 0;

    if ((len_byte & 0xC0) == 0x00) {
        packet_len_bytes = 1;
        actual_packet_length = len_byte & 0x3F;
    } else if ((len_byte & 0xC0) == 0x40) {
        packet_len_bytes = 2;
        if (pos + 2 > nbytes) return 0;
        actual_packet_length = ((uint64_t)(len_byte & 0x3F) << 8) | buffer[pos + 1];
    } else if ((len_byte & 0xC0) == 0x80) {
        packet_len_bytes = 4;
        if (pos + 4 > nbytes) return 0;
        actual_packet_length = ((uint64_t)(len_byte & 0x3F) << 24) | ((uint64_t)buffer[pos+1] << 16) | ((uint64_t)buffer[pos+2] << 8) | buffer[pos+3];
    }
    pos += packet_len_bytes;

    size_t real_packet_len = length_field_pos + packet_len_bytes + (size_t)actual_packet_length;
    if (real_packet_len > nbytes) real_packet_len = nbytes;

    *out_pn_offset = pos;
    *out_real_packet_len = real_packet_len;
    return 1;
}

// Helper untuk mengekstrak payload TLS dari dalam QUIC CRYPTO Frame
// Format CRYPTO Frame: Type (1 byte, biasanya 0x06) + Offset (varint) + Length (varint) + Data (TLS bytes)
static const unsigned char *quic_extract_tls_from_crypto_frame(
    const unsigned char *payload, size_t payload_len, size_t *out_tls_len
) {
    if (payload_len < 3) return NULL;
    
    size_t pos = 0;
    if (payload[pos++] != 0x06) { // Pastikan ini CRYPTO Frame (0x06)
        return NULL;
    }

    // Parse Offset Varint
    uint64_t offset = 0; // <-- PASTIKAN INI ADA
    if (pos >= payload_len) return NULL;
    uint8_t fb = payload[pos++];
    size_t varint_len = 1;

    if ((fb & 0xC0) == 0x00) {
        offset = fb & 0x3F;
        varint_len = 1;
    } else if ((fb & 0xC0) == 0x40) {
        if (pos + 1 > payload_len) return NULL;
        offset = ((uint64_t)(fb & 0x3F) << 8) | payload[pos++];
        varint_len = 2;
    } else if ((fb & 0xC0) == 0x80) {
        if (pos + 3 > payload_len) return NULL;
        offset = ((uint64_t)(fb & 0x3F) << 24) | 
                 ((uint64_t)payload[pos] << 16) | 
                 ((uint64_t)payload[pos+1] << 8) | 
                 (uint64_t)payload[pos+2];
        pos += 3;
        varint_len = 4;
    } else {
        if (pos + 7 > payload_len) return NULL;
        // 8-byte varint parsing jika diperlukan
        pos += 7;
    }
    (void)offset; // Supaya tidak ada warning unused variable
    (void)varint_len;

    // Parse Length Varint
    if (pos >= payload_len) return NULL;
    fb = payload[pos++];
    uint64_t crypto_len = 0;

    if ((fb & 0xC0) == 0x00) {
        crypto_len = fb & 0x3F;
    } else if ((fb & 0xC0) == 0x40) {
        if (pos + 1 > payload_len) return NULL;
        crypto_len = ((uint64_t)(fb & 0x3F) << 8) | payload[pos++];
    } else if ((fb & 0xC0) == 0x80) {
        if (pos + 3 > payload_len) return NULL;
        crypto_len = ((uint64_t)(fb & 0x3F) << 24) | 
                     ((uint64_t)payload[pos] << 16) | 
                     ((uint64_t)payload[pos+1] << 8) | 
                     (uint64_t)payload[pos+2];
        pos += 3;
    }

    if (pos + (size_t)crypto_len > payload_len) return NULL;

    *out_tls_len = (size_t)crypto_len;
    return &payload[pos];
}

// Di dalam struct QuicConnection (pastikan Anda menambahkan flag ini jika belum ada):
// bool has_sent_initial;

// Di dalam fungsi quic_feed_ssl_and_respond / event loop:
static void quic_feed_ssl_and_respond(SSL *ssl, QuicConnection *conn, int sock_server, 
                                     const unsigned char *feed_buffer, size_t feed_len,
                                     const unsigned char *client_dcid, size_t client_dcid_len,
                                     const unsigned char *client_scid, size_t client_scid_len,
                                     int is_retransmit) {
    
    // --- PENANGANAN RETRANSMISI DENGAN CACHE TERPISAH (MTU SAFE) ---
    if (is_retransmit && !feed_len) {
        if (conn->has_cached_response) {
            sendto(sock_server, conn->initial_cache, conn->initial_cache_len, 0,
                   (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
            
            if (conn->handshake_cache_len > 0) {
                sendto(sock_server, conn->handshake_cache, conn->handshake_cache_len, 0,
                       (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
                print_outbound_hex_dump("RETRANSMIT", conn->handshake_cache, conn->handshake_cache_len, 25);
            }

            fprintf(stderr, "[QUIC RETRANSMIT] Mengirim ulang Initial (%zu bytes) & Handshake (%zu bytes) terpisah ke klien.\n", 
                    conn->initial_cache_len, conn->handshake_cache_len);
        } else {
            fprintf(stderr, "[QUIC RETRANSMIT] Tidak ada cache respons yang tersedia untuk koneksi ini.\n");
        }
        return; 
    }

    if (feed_len > 0) {
        BIO *rbio = SSL_get_rbio(ssl);
        if (!rbio) {
            rbio = BIO_new(BIO_s_mem());
            SSL_set_bio(ssl, rbio, BIO_new(BIO_s_mem()));
        }
        BIO_write(rbio, feed_buffer, (int)feed_len);

        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            int ssl_err = SSL_get_error(ssl, ret);
            if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
                unsigned long err_code = ERR_get_error();
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                fprintf(stderr, "[QUIC SSL ERROR] OpenSSL error: %s\n", err_buf);
            }
        }
    }

    BIO *wbio = SSL_get_wbio(ssl);
    if (wbio) {
        // Parse wbio record demi record secara presisi
        while (BIO_pending(wbio) >= 5) {
            unsigned char header[5];
            if (BIO_read(wbio, header, 5) != 5) break;

            uint8_t record_type = header[0];
            size_t record_len = ((size_t)header[3] << 8) | (size_t)header[4];

            if (record_len > 8192) break; // Safety guard

            unsigned char record_payload[8192];
            if ((size_t)BIO_read(wbio, record_payload, record_len) != record_len) break;

            fprintf(stderr, "[QUIC TLS RECORD] Type: 0x%02x, Len: %zu\n", record_type, record_len);

            // --- TIPE 0x16: HANDSHAKE RECORD ---
            if (record_type == 0x16) {
                // Cek apakah ini ServerHello (Handshake message type 0x02)
                if (record_payload[0] == 0x02) {
                    size_t sh_len = ((size_t)record_payload[1] << 16) |
                                    ((size_t)record_payload[2] << 8) |
                                    ((size_t)record_payload[3]);
                    size_t total_server_hello_len = 4 + sh_len;

                    const unsigned char *pure_tls_msg = record_payload;
                    size_t pure_tls_len = total_server_hello_len;

                    unsigned char initial_secret[32];
                    unsigned char server_initial_secret[32];
                    unsigned char server_key[16];
                    unsigned char server_iv[12];
                    unsigned char server_hp[16];

                    unsigned char quic_packet_out[2048];
                    size_t quic_packet_len = 0;

                    if (quic_derive_initial_secret(client_dcid, client_dcid_len, initial_secret) &&
                        quic_hkdf_expand_label(initial_secret, "server in", NULL, 0, server_initial_secret, 32)) {
                        
                        quic_hkdf_expand_label(server_initial_secret, "quic key", NULL, 0, server_key, 16);
                        quic_hkdf_expand_label(server_initial_secret, "quic iv", NULL, 0, server_iv, 12);
                        quic_hkdf_expand_label(server_initial_secret, "quic hp", NULL, 0, server_hp, 16);

                        unsigned char assembled_plaintext[4096];
                        size_t assembled_len = quic_build_server_initial_payload(
                            conn->next_packet_number,
                            pure_tls_msg, pure_tls_len,
                            assembled_plaintext
                        );

                        if (quic_encrypt_server_initial(
                            assembled_plaintext, assembled_len,
                            client_scid, client_scid_len, 
                            client_dcid, client_dcid_len, 
                            conn->next_packet_number,
                            server_key, server_iv, server_hp,
                            quic_packet_out, &quic_packet_len
                        )) {
                            conn->next_packet_number++;
                            fprintf(stderr, "[QUIC CRYPTO] ServerInitial berhasil disiapkan! Len: %zu\n", quic_packet_len);
                        }
                    }

                    if (quic_packet_len > 0) {
                        sendto(sock_server, quic_packet_out, quic_packet_len, 0, 
                               (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
                        fprintf(stderr, "[QUIC MTU] Sukses mengirim ServerInitial terpisah (%zu bytes)\n", quic_packet_len);

                        memcpy(conn->initial_cache, quic_packet_out, quic_packet_len);
                        conn->initial_cache_len = quic_packet_len;
                        conn->has_cached_response = 1;
                    }

                    // Jika ada sisa data di dalam record ServerHello ini
                    size_t consumed_bytes = total_server_hello_len;
                    if (record_len > consumed_bytes) {
                        const unsigned char *remaining_tls = record_payload + consumed_bytes;
                        size_t remaining_tls_len = record_len - consumed_bytes;

                        if (!conn->has_server_hs_secret) {
                            fprintf(stderr, "[QUIC INFO] Server Handshake Secret belum tersedia. Menunda sisa handshake...\n");
                            break;
                        }

                        // Bungkus sisa handshake ke QUIC Handshake Packet
                        unsigned char hs_crypto_frame[8192];
                        size_t hs_cf_pos = 0;
                        hs_crypto_frame[hs_cf_pos++] = 0x06; 
                        hs_crypto_frame[hs_cf_pos++] = 0x00; 

                        if (remaining_tls_len < 64) {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)remaining_tls_len;
                        } else if (remaining_tls_len < 16384) {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x40 | (remaining_tls_len >> 8));
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(remaining_tls_len & 0xFF);
                        } else {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x80 | (remaining_tls_len >> 24));
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)((remaining_tls_len >> 16) & 0xFF);
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)((remaining_tls_len >> 8) & 0xFF);
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(remaining_tls_len & 0xFF);
                        }

                        memcpy(hs_crypto_frame + hs_cf_pos, remaining_tls, remaining_tls_len);
                        hs_cf_pos += remaining_tls_len;

                        unsigned char hs_packet_out[4096];
                        size_t hs_pkt_pos = 0;

                        hs_packet_out[hs_pkt_pos++] = 0xE0 | 0x00; 
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x01;

                        hs_packet_out[hs_pkt_pos++] = (unsigned char)client_scid_len;
                        memcpy(hs_packet_out + hs_pkt_pos, client_scid, client_scid_len);
                        hs_pkt_pos += client_scid_len;

                        hs_packet_out[hs_pkt_pos++] = (unsigned char)client_dcid_len;
                        memcpy(hs_packet_out + hs_pkt_pos, client_dcid, client_dcid_len);
                        hs_pkt_pos += client_dcid_len;

                        size_t hs_tag_len = 16;
                        size_t hs_remaining_len = 1 + hs_cf_pos + hs_tag_len;
 
                        if (hs_remaining_len < 64) {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)hs_remaining_len;
                        } else if (hs_remaining_len < 16384) {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x40 | (hs_remaining_len >> 8));
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                        } else {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x80 | (hs_remaining_len >> 24));
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 16) & 0xFF);
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 8) & 0xFF);
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                        }

                        size_t hs_pn_offset = hs_pkt_pos;
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(conn->next_handshake_packet_number & 0xFF);

                        size_t hs_aad_len = hs_pkt_pos;
                        const unsigned char *hs_aad = hs_packet_out;

                        unsigned char hs_key[16];
                        unsigned char hs_iv[12];
                        unsigned char hs_hp[16];

                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic key", NULL, 0, hs_key, 16);
                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic iv", NULL, 0, hs_iv, 12);
                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic hp", NULL, 0, hs_hp, 16);

                        unsigned char hs_nonce[12];
                        memcpy(hs_nonce, hs_iv, 12);
                        for (size_t k = 0; k < 8; k++) {
                            hs_nonce[11 - k] ^= (unsigned char)(conn->next_handshake_packet_number >> (8 * k));
                        }

                        EVP_CIPHER_CTX *hs_ctx = EVP_CIPHER_CTX_new();
                        if (hs_ctx) {
                            int len = 0, ct_len = 0;
                            unsigned char *ct_dest = hs_packet_out + hs_pkt_pos;

                            if (EVP_EncryptInit_ex(hs_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
                                EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
                                EVP_EncryptInit_ex(hs_ctx, NULL, NULL, hs_key, hs_nonce) &&
                                EVP_EncryptUpdate(hs_ctx, NULL, &len, hs_aad, (int)hs_aad_len) &&
                                EVP_EncryptUpdate(hs_ctx, ct_dest, &len, hs_crypto_frame, (int)hs_cf_pos)) {
                                
                                ct_len = len;
                                hs_pkt_pos += ct_len;

                                unsigned char hs_tag[16];
                                if (EVP_EncryptFinal_ex(hs_ctx, ct_dest + ct_len, &len) &&
                                    EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_GET_TAG, 16, hs_tag)) {
                                    
                                    memcpy(ct_dest + ct_len, hs_tag, 16);
                                    hs_pkt_pos += 16;

                                    size_t sample_off = hs_pn_offset + 4;
                                    unsigned char sample[16];
                                    memcpy(sample, hs_packet_out + sample_off, 16);

                                    unsigned char mask[16];
                                    int outlen = 0;
                                    EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
                                    if (hp_ctx) {
                                        if (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, hs_hp, NULL)) {
                                            EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
                                            EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
                                            
                                            hs_packet_out[0] ^= (mask[0] & 0x0f);
                                            hs_packet_out[hs_pn_offset] ^= mask[1];
                                        }
                                        EVP_CIPHER_CTX_free(hp_ctx);
                                    }

                                    print_outbound_hex_dump("INIT_FIRST_SEND", hs_packet_out, hs_pkt_pos, hs_pn_offset);

                                    sendto(sock_server, hs_packet_out, hs_pkt_pos, 0, 
                                           (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
                                    
                                    conn->next_handshake_packet_number++;
                                    fprintf(stderr, "[QUIC MTU] Sukses mengirim Handshake Packet terpisah (%zu bytes)\n", hs_pkt_pos);

                                    memcpy(conn->handshake_cache, hs_packet_out, hs_pkt_pos);
                                    conn->handshake_cache_len = hs_pkt_pos;
                                }
                            }
                            EVP_CIPHER_CTX_free(hs_ctx);
                        }
                    }
                } else {
                    // Record handshake lanjutan (EncryptedExtensions, Certificate, dsb.) jika sudah ada secret
                    if (conn->has_server_hs_secret) {
                        // Bungkus sebagai QUIC Handshake Packet
                        unsigned char hs_crypto_frame[8192];
                        size_t hs_cf_pos = 0;
                        hs_crypto_frame[hs_cf_pos++] = 0x06; 
                        hs_crypto_frame[hs_cf_pos++] = 0x00; 

                        if (record_len < 64) {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)record_len;
                        } else if (record_len < 16384) {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x40 | (record_len >> 8));
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(record_len & 0xFF);
                        } else {
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x80 | (record_len >> 24));
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)((record_len >> 16) & 0xFF);
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)((record_len >> 8) & 0xFF);
                            hs_crypto_frame[hs_cf_pos++] = (unsigned char)(record_len & 0xFF);
                        }

                        memcpy(hs_crypto_frame + hs_cf_pos, record_payload, record_len);
                        hs_cf_pos += record_len;

                        unsigned char hs_packet_out[4096];
                        size_t hs_pkt_pos = 0;

                        hs_packet_out[hs_pkt_pos++] = 0xE0 | 0x00; 
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x00;
                        hs_packet_out[hs_pkt_pos++] = 0x01;

                        hs_packet_out[hs_pkt_pos++] = (unsigned char)client_scid_len;
                        memcpy(hs_packet_out + hs_pkt_pos, client_scid, client_scid_len);
                        hs_pkt_pos += client_scid_len;

                        hs_packet_out[hs_pkt_pos++] = (unsigned char)client_dcid_len;
                        memcpy(hs_packet_out + hs_pkt_pos, client_dcid, client_dcid_len);
                        hs_pkt_pos += client_dcid_len;

                        size_t hs_tag_len = 16;
                        size_t hs_remaining_len = 1 + hs_cf_pos + hs_tag_len;
 
                        if (hs_remaining_len < 64) {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)hs_remaining_len;
                        } else if (hs_remaining_len < 16384) {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x40 | (hs_remaining_len >> 8));
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                        } else {
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x80 | (hs_remaining_len >> 24));
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 16) & 0xFF);
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 8) & 0xFF);
                            hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                        }

                        size_t hs_pn_offset = hs_pkt_pos;
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(conn->next_handshake_packet_number & 0xFF);

                        size_t hs_aad_len = hs_pkt_pos;
                        const unsigned char *hs_aad = hs_packet_out;

                        unsigned char hs_key[16];
                        unsigned char hs_iv[12];
                        unsigned char hs_hp[16];

                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic key", NULL, 0, hs_key, 16);
                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic iv", NULL, 0, hs_iv, 12);
                        quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic hp", NULL, 0, hs_hp, 16);

                        unsigned char hs_nonce[12];
                        memcpy(hs_nonce, hs_iv, 12);
                        for (size_t k = 0; k < 8; k++) {
                            hs_nonce[11 - k] ^= (unsigned char)(conn->next_handshake_packet_number >> (8 * k));
                        }

                        EVP_CIPHER_CTX *hs_ctx = EVP_CIPHER_CTX_new();
                        if (hs_ctx) {
                            int len = 0, ct_len = 0;
                            unsigned char *ct_dest = hs_packet_out + hs_pkt_pos;

                            if (EVP_EncryptInit_ex(hs_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
                                EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
                                EVP_EncryptInit_ex(hs_ctx, NULL, NULL, hs_key, hs_nonce) &&
                                EVP_EncryptUpdate(hs_ctx, NULL, &len, hs_aad, (int)hs_aad_len) &&
                                EVP_EncryptUpdate(hs_ctx, ct_dest, &len, hs_crypto_frame, (int)hs_cf_pos)) {
                                
                                ct_len = len;
                                hs_pkt_pos += ct_len;

                                unsigned char hs_tag[16];
                                if (EVP_EncryptFinal_ex(hs_ctx, ct_dest + ct_len, &len) &&
                                    EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_GET_TAG, 16, hs_tag)) {
                                    
                                    memcpy(ct_dest + ct_len, hs_tag, 16);
                                    hs_pkt_pos += 16;

                                    size_t sample_off = hs_pn_offset + 4;
                                    unsigned char sample[16];
                                    memcpy(sample, hs_packet_out + sample_off, 16);

                                    unsigned char mask[16];
                                    int outlen = 0;
                                    EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
                                    if (hp_ctx) {
                                        if (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, hs_hp, NULL)) {
                                            EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
                                            EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
                                            
                                            hs_packet_out[0] ^= (mask[0] & 0x0f);
                                            hs_packet_out[hs_pn_offset] ^= mask[1];
                                        }
                                        EVP_CIPHER_CTX_free(hp_ctx);
                                    }

                                    sendto(sock_server, hs_packet_out, hs_pkt_pos, 0, 
                                           (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
                                    
                                    conn->next_handshake_packet_number++;
                                    fprintf(stderr, "[QUIC MTU] Sukses mengirim Handshake Packet lanjutan (%zu bytes)\n", hs_pkt_pos);
                                }
                            }
                            EVP_CIPHER_CTX_free(hs_ctx);
                        }
                    }
                }
            } 
            // --- TIPE 0x17: ENCRYPTED / APPLICATION DATA RECORD ---
            else if (record_type == 0x17) {
                if (conn->has_server_hs_secret) {
                    // 1. Rekonstruksi record TLS asli (Header 5 byte + Payload)
                    unsigned char tls_full_record[8192];
                    tls_full_record[0] = record_type;
                    tls_full_record[1] = 0x03;
                    tls_full_record[2] = 0x03;
                    tls_full_record[3] = (unsigned char)(record_len >> 8);
                    tls_full_record[4] = (unsigned char)(record_len & 0xFF);
                    memcpy(tls_full_record + 5, record_payload, record_len);
                    size_t tls_full_len = 5 + record_len;

                    // 2. Bungkus ke dalam QUIC CRYPTO Frame (Type 0x06, Offset dinamis/0, Length)
                    unsigned char hs_crypto_frame[8192];
                    size_t hs_cf_pos = 0;
                    hs_crypto_frame[hs_cf_pos++] = 0x06; // CRYPTO Frame Type
                    hs_crypto_frame[hs_cf_pos++] = 0x00; // Offset 0 (atau sesuaikan jika multi-frame)

                    // Varint encoding untuk length tls_full_len
                    if (tls_full_len < 64) {
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)tls_full_len;
                    } else if (tls_full_len < 16384) {
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x40 | (tls_full_len >> 8));
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)(tls_full_len & 0xFF);
                    } else {
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)(0x80 | (tls_full_len >> 24));
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)((tls_full_len >> 16) & 0xFF);
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)((tls_full_len >> 8) & 0xFF);
                        hs_crypto_frame[hs_cf_pos++] = (unsigned char)(tls_full_len & 0xFF);
                    }

                    memcpy(hs_crypto_frame + hs_cf_pos, tls_full_record, tls_full_len);
                    hs_cf_pos += tls_full_len;

                    // 3. Susun Header QUIC Handshake Packet (Long Header, Type Handshake = 0x20 | 0x03)
                    unsigned char hs_packet_out[4096];
                    size_t hs_pkt_pos = 0;

                    hs_packet_out[hs_pkt_pos++] = 0xE0 | 0x02; // Handshake Packet Type (Long Header)
                    // Version (4 bytes)
                    hs_packet_out[hs_pkt_pos++] = 0x00;
                    hs_packet_out[hs_pkt_pos++] = 0x00;
                    hs_packet_out[hs_pkt_pos++] = 0x00;
                    hs_packet_out[hs_pkt_pos++] = 0x01;

                    // Dest Connection ID (DCID) dari client SCID
                    hs_packet_out[hs_pkt_pos++] = (unsigned char)client_scid_len;
                    memcpy(hs_packet_out + hs_pkt_pos, client_scid, client_scid_len);
                    hs_pkt_pos += client_scid_len;

                    // Source Connection ID (SCID) dari client DCID
                    hs_packet_out[hs_pkt_pos++] = (unsigned char)client_dcid_len;
                    memcpy(hs_packet_out + hs_pkt_pos, client_dcid, client_dcid_len);
                    hs_pkt_pos += client_dcid_len;

                    // Length field placeholder / hitung sisa
                    size_t hs_tag_len = 16;
                    size_t hs_remaining_len = 1 /* Packet Number */ + hs_cf_pos + hs_tag_len;

                    if (hs_remaining_len < 64) {
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)hs_remaining_len;
                    } else if (hs_remaining_len < 16384) {
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x40 | (hs_remaining_len >> 8));
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                    } else {
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(0x80 | (hs_remaining_len >> 24));
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 16) & 0xFF);
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)((hs_remaining_len >> 8) & 0xFF);
                        hs_packet_out[hs_pkt_pos++] = (unsigned char)(hs_remaining_len & 0xFF);
                    }

                    size_t hs_pn_offset = hs_pkt_pos;
                    hs_packet_out[hs_pkt_pos++] = (unsigned char)(conn->next_handshake_packet_number & 0xFF);

                    size_t hs_aad_len = hs_pkt_pos;
                    const unsigned char *hs_aad = hs_packet_out;

                    // 4. Turunkan Kunci Enkripsi Handshake (AES-128-GCM)
                    unsigned char hs_key[16], hs_iv[12], hs_hp[16];
                    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic key", NULL, 0, hs_key, 16);
                    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic iv", NULL, 0, hs_iv, 12);
                    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic hp", NULL, 0, hs_hp, 16);

                    unsigned char hs_nonce[12];
                    memcpy(hs_nonce, hs_iv, 12);
                    for (size_t k = 0; k < 8; k++) {
                        hs_nonce[11 - k] ^= (unsigned char)(conn->next_handshake_packet_number >> (8 * k));
                    }

                    // 5. Enkripsi Payload dengan AES-GCM
                    EVP_CIPHER_CTX *hs_ctx = EVP_CIPHER_CTX_new();
                    if (hs_ctx) {
                        int len = 0, ct_len = 0;
                        unsigned char *ct_dest = hs_packet_out + hs_pkt_pos;

                        if (EVP_EncryptInit_ex(hs_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
                            EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
                            EVP_EncryptInit_ex(hs_ctx, NULL, NULL, hs_key, hs_nonce) &&
                            EVP_EncryptUpdate(hs_ctx, NULL, &len, hs_aad, (int)hs_aad_len) &&
                            EVP_EncryptUpdate(hs_ctx, ct_dest, &len, hs_crypto_frame, (int)hs_cf_pos)) {
                            
                            ct_len = len;
                            hs_pkt_pos += ct_len;

                            unsigned char hs_tag[16];
                            if (EVP_EncryptFinal_ex(hs_ctx, ct_dest + ct_len, &len) &&
                                EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_GET_TAG, 16, hs_tag)) {
                                
                                memcpy(ct_dest + ct_len, hs_tag, 16);
                                hs_pkt_pos += 16;

                                // 6. Header Protection Masking
                                size_t sample_off = hs_pn_offset + 4;
                                unsigned char sample[16];
                                memcpy(sample, hs_packet_out + sample_off, 16);

                                unsigned char mask[16];
                                int outlen = 0;
                                EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
                                if (hp_ctx) {
                                    if (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, hs_hp, NULL)) {
                                        EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
                                        EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
                                        
                                        hs_packet_out[0] ^= (mask[0] & 0x0f);
                                        hs_packet_out[hs_pn_offset] ^= mask[1];
                                    }
                                    EVP_CIPHER_CTX_free(hp_ctx);
                                }

                                // 7. Kirim Paket ke Klien via UDP
                                sendto(sock_server, hs_packet_out, hs_pkt_pos, 0, 
                                       (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);
                                
                                conn->next_handshake_packet_number++;
                                fprintf(stderr, "[QUIC MTU] Sukses mengirim Encrypted Handshake Packet (0x17) (%zu bytes)\n", hs_pkt_pos);
                            }
                        }
                        EVP_CIPHER_CTX_free(hs_ctx);
                    }
                }
            }
        }
    }
}

// Fungsi Utama Event Loop (Kini Sangat Ringkas & Mudah Dirawat)
static void* quic_event_loop_run_thread(void *arg) {
    (void)arg;
    uint8_t buffer[65535];
    struct sockaddr_in client_addr;

    while (atomic_load(&quic_poller.running)) {
        int n = epoll_wait(quic_poller.epoll_fd, g_quic_events, adaptive_hw_aware.event_batch_size, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break; 
        }

        for (int i = 0; i < n; i++) {
            int current_fd = g_quic_events[i].data.fd;

            if (current_fd == quic_poller.sock_server) {
                while (atomic_load(&quic_poller.running)) {
                    socklen_t addr_len = sizeof(client_addr);
                    memset(&client_addr, 0, sizeof(client_addr));

                    ssize_t nbytes = recvfrom(quic_poller.sock_server, buffer, sizeof(buffer), 0,
                                              (struct sockaddr *)&client_addr, &addr_len);
                    
                    if (nbytes < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break; 
                        if (errno == EINTR) continue;
                        break;
                    }
                    if (nbytes == 0) break;

                    uint8_t dcid_buffer[MAX_DCID_LEN];
                    uint8_t dcid_len = 0;

                    // --- DETEKSI LONG HEADER VS SHORT HEADER (1-RTT) ---
                    int is_long_header = (buffer[0] & 0x80) != 0;
                    QuicConnection *conn = NULL;

                    if (is_long_header) {
                        if (quic_extract_dcid(buffer, (size_t)nbytes, dcid_buffer, &dcid_len) < 0) {
                            sendto(quic_poller.sock_server, buffer, nbytes, 0, (struct sockaddr *)&client_addr, addr_len);
                            continue;
                        }
                        conn = core_quic_conn_table_find(&quic_conn_table, dcid_buffer, dcid_len);
                    } else {
                        // Short Header (1-RTT): Ambil DCID dengan asumsi panjang DCID standar (8 byte)
                        dcid_len = 8; 
                        if ((size_t)nbytes > (1 + (size_t)dcid_len)) {
                            memcpy(dcid_buffer, buffer + 1, dcid_len);
                            conn = core_quic_conn_table_find(&quic_conn_table, dcid_buffer, dcid_len);
                        }
                    }

                    if (conn == NULL) {
                        QuicConnection *new_conn = (QuicConnection*)malloc(sizeof(QuicConnection));
                        if (new_conn && is_long_header) {
                            memset(new_conn, 0, sizeof(QuicConnection));
                            memcpy(new_conn->dcid, dcid_buffer, dcid_len);
                            new_conn->dcid_len = dcid_len;
                            memcpy(&new_conn->client_addr, &client_addr, sizeof(client_addr));
                            new_conn->client_addr_len = addr_len;
                            new_conn->state = QUIC_STATE_HANDSHAKE;
                            new_conn->next_packet_number = 0;
                            new_conn->next_handshake_packet_number = 0;
                            new_conn->has_sent_initial = 0;
                            new_conn->sock_server = quic_poller.sock_server;

                            SSL *quic_ssl = SSL_new(halmos_quic_tls_ctx);
                            if (!quic_ssl) {
                                free(new_conn);
                                continue;
                            }

                            SSL_set_app_data(quic_ssl, new_conn);
                            SSL_set_accept_state(quic_ssl);
                            quic_ssl_set_for_conn(new_conn, quic_ssl);

                            if (core_quic_conn_table_insert(&quic_conn_table, new_conn)) {
                                conn = new_conn;
                            } else {
                                quic_ssl_free_for_conn(new_conn);
                                free(new_conn);
                                continue;
                            }
                        } else {
                            if (new_conn) free(new_conn);
                            continue;
                        }
                    } else {
                        if (conn->client_addr.sin_port != client_addr.sin_port || 
                            conn->client_addr.sin_addr.s_addr != client_addr.sin_addr.s_addr) {
                            memcpy(&conn->client_addr, &client_addr, sizeof(client_addr));
                        }
                    }

                    if (conn != NULL) {
                        SSL *ssl = quic_ssl_get_for_conn(conn);
                        if (ssl) {
                            const unsigned char *feed_buffer = buffer;
                            size_t feed_len = (size_t)nbytes;
                            uint8_t decrypted_payload[65535];
                            size_t decrypted_len = 0;

                            size_t pn_offset = 0, real_packet_len = 0;
                            const unsigned char *pkt_dcid_ptr = NULL;
                            uint8_t pkt_dcid_len = 0;
                            const unsigned char *pkt_scid_ptr = NULL; 
                            uint8_t pkt_scid_len = 0;
                            int pkt_type = 0; 
                            int decrypt_ok = 0;

                            if (!is_long_header) {
                                // --- PENANGANAN PAKET 1-RTT (SHORT HEADER) ---
                                if (conn->has_client_app_secret) {
                                    decrypt_ok = quic_handle_1rtt_decryption(
                                        buffer, (size_t)nbytes,
                                        conn->client_application_traffic_secret_0,
                                        conn->dcid_len,
                                        decrypted_payload, &decrypted_len
                                    );
                                    fprintf(stderr, "[QUIC 1-RTT IN] Menerima & mendekripsi paket 1-RTT dari klien! Status: %d, Len: %zu\n", decrypt_ok, decrypted_len);
                                }
                                pkt_type = 3; 

                                // PENTING: Langsung lewati pemanggilan feed_ssl_and_respond untuk Short Header 1-RTT!
                                continue; 
                            } else {
                                // --- PENANGANAN LONG HEADER (Initial / Handshake) ---
                                
                                // FILTER RETRANSMISI: Abaikan long header jika server sudah siap 1-RTT
                                if (conn->has_server_app_secret) {
                                    continue; 
                                }

                                if (quic_parse_packet_header(buffer, (size_t)nbytes, &pn_offset, &real_packet_len, 
                                 &pkt_dcid_ptr, &pkt_dcid_len, &pkt_scid_ptr, &pkt_scid_len, &pkt_type)) {
                                    
                                    if (pkt_type == 0) {
                                        decrypt_ok = quic_handle_decryption(buffer, real_packet_len, pn_offset, pkt_dcid_ptr, pkt_dcid_len, decrypted_payload, &decrypted_len);
                                    } else if (pkt_type == 2) {
                                        if (conn->has_client_hs_secret) {
                                            decrypt_ok = quic_handle_handshake_decryption(
                                                buffer, real_packet_len, pn_offset, 
                                                conn->client_handshake_secret, 
                                                decrypted_payload, &decrypted_len
                                            );
                                        } else {
                                            fprintf(stderr, "[QUIC WARNING] Menerima Handshake packet, tetapi client_hs_secret belum tersedia!\n");
                                            decrypt_ok = 0;
                                        }
                                        fprintf(stderr, "[QUIC HANDSHAKE IN] Menerima & mendekripsi paket Handshake dari klien! Status: %d\n", decrypt_ok);
                                    }
                                }
                            }

                            if (decrypt_ok && pkt_type != 3) {
                                size_t tls_raw_len = 0;
                                const unsigned char *tls_raw_data = quic_extract_tls_from_crypto_frame(
                                    decrypted_payload, decrypted_len, &tls_raw_len
                                );

                                if (tls_raw_data && tls_raw_len > 0) {
                                    static unsigned char tls_record_buf[65535];
                                    if (tls_raw_len + 5 <= sizeof(tls_record_buf)) {
                                        tls_record_buf[0] = 0x16; 
                                        tls_record_buf[1] = 0x03;
                                        tls_record_buf[2] = 0x03;
                                        tls_record_buf[3] = (unsigned char)(tls_raw_len >> 8);
                                        tls_record_buf[4] = (unsigned char)(tls_raw_len & 0xFF);
                                        
                                        memcpy(tls_record_buf + 5, tls_raw_data, tls_raw_len);
                                        
                                        feed_buffer = tls_record_buf;
                                        feed_len = tls_raw_len + 5;
                                    }
                                }
                                fprintf(stderr, "[QUIC CRYPTO] Sukses mendekripsi & mengekstrak TLS murni dari paket tipe %d! Len: %zu\n", pkt_type, tls_raw_len);
                            }

                            int is_retransmit = 0;
                            if (conn->state == QUIC_STATE_HANDSHAKE && conn->has_sent_initial && pkt_type == 0 && decrypted_len == 0) {
                                is_retransmit = 1;
                            }

                            if (pkt_type != 3) {
                                quic_feed_ssl_and_respond(ssl, conn, quic_poller.sock_server, 
                                                        feed_buffer, feed_len, 
                                                        pkt_dcid_ptr, pkt_dcid_len, 
                                                        pkt_scid_ptr, pkt_scid_len, 
                                                        is_retransmit); 

                                if (!is_retransmit && pkt_type == 0) {
                                    conn->has_sent_initial = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}
