#include "halmos_core_quic_thread_pool.h"
#include "halmos_core_quic_event_loop.h"
#include "halmos_core_quic_queue.h"
#include "halmos_core_quic_conn_table.h"
#include "halmos_core_quic_parser.h"
#include "halmos_sec_quic_tls.h"
#include "halmos_sec_quic_crypto.h"
#include "halmos_global.h"
#include "halmos_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#define TLS_MAX_RECORD_PAYLOAD 16384U

extern QuicConnTable quic_conn_table;

enum {
    QUIC_FSM_CLOSE_OR_ERR = -1,
    QUIC_FSM_DONE         = 0,
    QUIC_FSM_NEED_MORE    = 1,
    QUIC_FSM_ACTIVE_1RTT  = 2
};

typedef struct {
    int saw_ack;
    uint64_t largest_acked_pn;
    int saw_crypto;
    size_t crypto_bytes_fed;
    int tls_handshake_done;
} QuicHandshakeFrameResult;

static size_t quic_read_varint(const unsigned char *buf, size_t buf_len, uint64_t *out_val) {
    if (!buf || !out_val || buf_len == 0) {
        return 0;
    }

    uint8_t first = buf[0];
    uint8_t prefix = first & 0xC0;
    size_t len = 0;
    uint64_t val = 0;

    if (prefix == 0x00) {
        len = 1;
        val = (uint64_t)(first & 0x3F);
    } else if (prefix == 0x40) {
        len = 2;
        if (buf_len < len) {
            return 0;
        }
        val = ((uint64_t)(first & 0x3F) << 8) |
              (uint64_t)buf[1];
    } else if (prefix == 0x80) {
        len = 4;
        if (buf_len < len) {
            return 0;
        }
        val = ((uint64_t)(first & 0x3F) << 24) |
              ((uint64_t)buf[1] << 16) |
              ((uint64_t)buf[2] << 8) |
              (uint64_t)buf[3];
    } else {
        len = 8;
        if (buf_len < len) {
            return 0;
        }
        val = ((uint64_t)(first & 0x3F) << 56) |
              ((uint64_t)buf[1] << 48) |
              ((uint64_t)buf[2] << 40) |
              ((uint64_t)buf[3] << 32) |
              ((uint64_t)buf[4] << 24) |
              ((uint64_t)buf[5] << 16) |
              ((uint64_t)buf[6] << 8) |
              (uint64_t)buf[7];
    }

    *out_val = val;
    return len;
}

static int quic_bio_write_tls_handshake_records(BIO *rbio,
                                               const unsigned char *tls_data,
                                               size_t tls_len) {
    if (!rbio || !tls_data || tls_len == 0) {
        return 0;
    }

    size_t offset = 0;
    while (offset < tls_len) {
        size_t chunk_len = tls_len - offset;
        if (chunk_len > TLS_MAX_RECORD_PAYLOAD) {
            chunk_len = TLS_MAX_RECORD_PAYLOAD;
        }

        size_t rec_len = 5 + chunk_len;
        if (rec_len > (size_t)INT_MAX) {
            fprintf(stderr, "[QUIC TLS REC ERR] Ukuran record terlalu besar: %zu\n", rec_len);
            return 0;
        }

        unsigned char *rec_buf = (unsigned char *)malloc(rec_len);
        if (!rec_buf) {
            fprintf(stderr, "[QUIC TLS REC ERR] Gagal alokasi %zu byte untuk TLS record\n", rec_len);
            return 0;
        }

        /* TLSPlaintext header: type(0x16=Handshake), legacy_record_version(0x0303), length(2B BE) */
        rec_buf[0] = 0x16;
        rec_buf[1] = 0x03;
        rec_buf[2] = 0x03;
        rec_buf[3] = (unsigned char)((chunk_len >> 8) & 0xFF);
        rec_buf[4] = (unsigned char)(chunk_len & 0xFF);

        memcpy(rec_buf + 5, tls_data + offset, chunk_len);

        int written = BIO_write(rbio, rec_buf, (int)rec_len);
        free(rec_buf);

        if (written != (int)rec_len) {
            fprintf(stderr, "[QUIC TLS REC ERR] BIO_write tidak penuh: written=%d expected=%zu\n",
                    written, rec_len);
            return 0;
        }

        offset += chunk_len;
    }

    return 1;
}

static void quic_step_hex_dump(const char *tag, const unsigned char *buf, size_t len) {
    fprintf(stderr, "%s (len=%zu):", tag, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, " %02x", buf[i]);
    }
    fprintf(stderr, "\n");
}

static int quic_feed_tls_crypto_and_step(
    SSL *ssl,
    const unsigned char *tls_data,
    size_t tls_len,
    int *out_hs_done
) {
    if (out_hs_done) {
        *out_hs_done = 0;
    }

    if (!ssl || !tls_data || tls_len == 0) {
        fprintf(stderr, "[QUIC STEP DBG] argumen tidak valid (ssl=%p, tls_data=%p, tls_len=%zu)\n",
                (void *)ssl, (const void *)tls_data, tls_len);
        return 0;
    }

    quic_step_hex_dump("[QUIC STEP IN HEX]", tls_data, tls_len);

    const char *st_before = SSL_state_string_long(ssl);
    fprintf(stderr, "[QUIC STEP DBG] state_before=%s\n", st_before ? st_before : "(null)");
    if (st_before && strstr(st_before, "error") != NULL) {
        fprintf(stderr, "[QUIC STEP DBG] skip karena ssl sudah error\n");
        return 0;
    }

    BIO *rbio = SSL_get_rbio(ssl);
    if (rbio) {
        char *rb_pre = NULL;
        long rb_pre_len = BIO_get_mem_data(rbio, &rb_pre);
        fprintf(stderr, "[QUIC STEP DBG] rbio_pending_before=%ld\n", rb_pre_len);
        if (rb_pre && rb_pre_len > 0) {
            quic_step_hex_dump("[QUIC STEP RBIO PRE]", (const unsigned char *)rb_pre, (size_t)rb_pre_len);
        }
    }

    QuicConnection *conn = (QuicConnection *)SSL_get_app_data(ssl);
    quic_tls_feed_incoming_bytes(ssl, conn, tls_data, tls_len, NULL, 0);

    const char *st_after = SSL_state_string_long(ssl);
    int is_finished = SSL_is_init_finished(ssl);
    fprintf(stderr, "[QUIC STEP DBG] state_after=%s, SSL_is_init_finished=%d\n",
            st_after ? st_after : "(null)", is_finished);

    rbio = SSL_get_rbio(ssl);
    if (rbio) {
        char *rb_post = NULL;
        long rb_post_len = BIO_get_mem_data(rbio, &rb_post);
        fprintf(stderr, "[QUIC STEP DBG] rbio_pending_after=%ld\n", rb_post_len);
        if (rb_post && rb_post_len > 0) {
            quic_step_hex_dump("[QUIC STEP RBIO POST]", (const unsigned char *)rb_post, (size_t)rb_post_len);
        }
    }

    if (st_after && strstr(st_after, "error") != NULL) {
        return 0;
    }

    if (out_hs_done && is_finished) {
        *out_hs_done = 1;
        fprintf(stderr, "[QUIC STEP DBG] Handshake TLS selesai (out_hs_done=1)\n");
    }

    return 1;
}

int quic_process_client_handshake_frames(
    SSL *ssl,
    const unsigned char *plain,
    size_t plain_len,
    QuicHandshakeFrameResult *res_out
) {
    if (!plain || plain_len == 0) {
        return 0;
    }

    QuicHandshakeFrameResult res;
    memset(&res, 0, sizeof(res));

    size_t pos = 0;
    while (pos < plain_len) {
        size_t frame_start = pos;
        uint64_t frame_type = 0;
        size_t vlen = quic_read_varint(plain + pos, plain_len - pos, &frame_type);
        if (vlen == 0 || pos + vlen > plain_len) {
            fprintf(stderr, "[QUIC HS FRAME] Gagal baca frame type di offset %zu\n", frame_start);
            return 0;
        }
        pos += vlen;

        if (frame_type == 0x00ULL) {
            /* PADDING */
            continue;
        }

        if (frame_type == 0x01ULL) {
            /* PING */
            continue;
        }

        if (frame_type == 0x1cULL || frame_type == 0x1dULL) {
            /* CONNECTION_CLOSE frame (RFC 9000 section 19.19) */
            uint64_t err_code = 0;
            uint64_t frame_trigger = 0;
            uint64_t reason_phrase_len = 0;

            size_t n_err = quic_read_varint(plain + pos, plain_len - pos, &err_code);
            if (n_err == 0 || pos + n_err > plain_len) {
                return 0;
            }
            pos += n_err;

            if (frame_type == 0x1cULL) {
                size_t n_trig = quic_read_varint(plain + pos, plain_len - pos, &frame_trigger);
                if (n_trig == 0 || pos + n_trig > plain_len) {
                    return 0;
                }
                pos += n_trig;
            }

            size_t n_rlen = quic_read_varint(plain + pos, plain_len - pos, &reason_phrase_len);
            if (n_rlen == 0 || pos + n_rlen > plain_len) {
                return 0;
            }
            pos += n_rlen;

            if (reason_phrase_len > plain_len - pos) {
                return 0;
            }
            pos += (size_t)reason_phrase_len;

            fprintf(stderr, "[QUIC HS FRAME] Diterima CONNECTION_CLOSE (err_code=0x%llx)\n",
                    (unsigned long long)err_code);

            if (res_out) {
                *res_out = res;
            }
            return 1;
        }

        if (frame_type == 0x02ULL || frame_type == 0x03ULL) {
            /* ACK atau ACK_ECN */
            uint64_t largest_ack = 0, ack_delay = 0, ack_range_cnt = 0, first_ack_range = 0;

            size_t n1 = quic_read_varint(plain + pos, plain_len - pos, &largest_ack);
            if (n1 == 0 || pos + n1 > plain_len) return 0;
            pos += n1;

            size_t n2 = quic_read_varint(plain + pos, plain_len - pos, &ack_delay);
            if (n2 == 0 || pos + n2 > plain_len) return 0;
            pos += n2;

            size_t n3 = quic_read_varint(plain + pos, plain_len - pos, &ack_range_cnt);
            if (n3 == 0 || pos + n3 > plain_len || ack_range_cnt > plain_len) return 0;
            pos += n3;

            size_t n4 = quic_read_varint(plain + pos, plain_len - pos, &first_ack_range);
            if (n4 == 0 || pos + n4 > plain_len) return 0;
            pos += n4;

            for (uint64_t r = 0; r < ack_range_cnt; r++) {
                uint64_t gap = 0, ack_range = 0;
                size_t ng = quic_read_varint(plain + pos, plain_len - pos, &gap);
                if (ng == 0 || pos + ng > plain_len) return 0;
                pos += ng;

                size_t nr = quic_read_varint(plain + pos, plain_len - pos, &ack_range);
                if (nr == 0 || pos + nr > plain_len) return 0;
                pos += nr;
            }

            if (frame_type == 0x03ULL) {
                /* ACK_ECN memiliki 3 field varint tambahan: ECT0, ECT1, ECN-CE */
                for (int e = 0; e < 3; e++) {
                    uint64_t ecn_val = 0;
                    size_t ne = quic_read_varint(plain + pos, plain_len - pos, &ecn_val);
                    if (ne == 0 || pos + ne > plain_len) return 0;
                    pos += ne;
                }
            }

            res.saw_ack = 1;
            res.largest_acked_pn = largest_ack;
            fprintf(stderr, "[QUIC HS FRAME] Diterima ACK (type=0x%llx, largest_acked=%llu, ranges=%llu)\n",
                    (unsigned long long)frame_type,
                    (unsigned long long)largest_ack,
                    (unsigned long long)ack_range_cnt);
            continue;
        }

        if (frame_type == 0x06ULL) {
            /* CRYPTO frame */
            uint64_t crypto_offset = 0, crypto_len_u64 = 0;

            size_t no = quic_read_varint(plain + pos, plain_len - pos, &crypto_offset);
            if (no == 0 || pos + no > plain_len) return 0;
            pos += no;

            size_t nl = quic_read_varint(plain + pos, plain_len - pos, &crypto_len_u64);
            if (nl == 0 || pos + nl > plain_len) return 0;
            pos += nl;

            if (crypto_len_u64 > plain_len - pos) {
                fprintf(stderr, "[QUIC HS FRAME] Panjang CRYPTO melebihi sisa payload (%llu > %zu)\n",
                        (unsigned long long)crypto_len_u64, plain_len - pos);
                return 0;
            }
            size_t crypto_len = (size_t)crypto_len_u64;

            fprintf(stderr, "[QUIC HS FRAME] Diterima CRYPTO (offset=%llu, len=%zu)\n",
                    (unsigned long long)crypto_offset, crypto_len);

            if (!quic_feed_tls_crypto_and_step(ssl, plain + pos, crypto_len, &res.tls_handshake_done)) {
                return 0;
            }

            pos += crypto_len;
            res.saw_crypto = 1;
            res.crypto_bytes_fed += crypto_len;
            continue;
        }

        fprintf(stderr, "[QUIC HS FRAME] Frame tidak didukung pada paket Handshake klien: 0x%llx (offset=%zu)\n",
                (unsigned long long)frame_type, frame_start);
        return 0;
    }

    if (res_out) {
        *res_out = res;
    }
    return 1;
}

static QuicConnection* quic_thread_pool_dispatch_connection(
    const uint8_t *dcid_buffer, uint8_t dcid_len, 
    struct sockaddr_in *client_addr, socklen_t addr_len, 
    int is_long_header
) {
    QuicConnection *conn = core_quic_conn_table_find(&quic_conn_table, dcid_buffer, dcid_len);

    if (conn == NULL) {
        // Koneksi baru hanya boleh diinisialisasi dari Long Header (Initial packet)
        if (!is_long_header) {
            return NULL;
        }

        QuicConnection *new_conn = (QuicConnection*)malloc(sizeof(QuicConnection));
        if (!new_conn) {
            return NULL;
        }

        memset(new_conn, 0, sizeof(QuicConnection));
        memcpy(new_conn->dcid, dcid_buffer, dcid_len);
        new_conn->dcid_len = dcid_len;
        memcpy(&new_conn->client_addr, client_addr, sizeof(*client_addr));
        new_conn->client_addr_len = addr_len;
        new_conn->state = QUIC_STATE_HANDSHAKE;
        new_conn->next_packet_number = 0;
        new_conn->next_handshake_packet_number = 0;
        new_conn->has_sent_initial = 0;
        new_conn->handshake_crypto_offset = 0;
        new_conn->tls_hs_seq_num = 0;
        new_conn->server_scid_len = 0;
        memset(new_conn->server_scid, 0, sizeof(new_conn->server_scid));
        new_conn->sock_server = core_quic_event_loop_get_server_fd();

        /* Nilai default cipher suite & panjang kunci sebelum negosiasi TLS 1.3 selesai */
        new_conn->cipher_suite = QUIC_CIPHER_UNKNOWN;
        new_conn->aead_key_len = 0;
        new_conn->secret_len = 0;

        SSL *quic_ssl = SSL_new(halmos_quic_tls_ctx);
        if (!quic_ssl) {
            free(new_conn);
            return NULL;
        }

        SSL_set_app_data(quic_ssl, new_conn);
        SSL_set_accept_state(quic_ssl);
        quic_ssl_set_for_conn(new_conn, quic_ssl);

        if (core_quic_conn_table_insert(&quic_conn_table, new_conn)) {
            conn = new_conn;
        } else {
            quic_ssl_free_for_conn(new_conn);
            free(new_conn);
            return NULL;
        }
    } else {
        // Perbarui port/alamat klien jika terjadi migrasi atau perubahan port NAT
        if (conn->client_addr.sin_port != client_addr->sin_port || 
            conn->client_addr.sin_addr.s_addr != client_addr->sin_addr.s_addr) {
            memcpy(&conn->client_addr, client_addr, sizeof(*client_addr));
            conn->client_addr_len = addr_len;
        }
    }

    return conn;
}

static int quic_thread_pool_handle_packet(
    const uint8_t *buffer, size_t nbytes,
    struct sockaddr_in *client_addr, socklen_t addr_len,
    const uint8_t *dcid, uint8_t dcid_len,
    bool has_dcid, bool is_long_header
) {
    (void)dcid;
    (void)dcid_len;
    (void)has_dcid;

    if (!buffer || nbytes == 0 || !client_addr) {
        return QUIC_FSM_CLOSE_OR_ERR;
    }

    int sock_fd = core_quic_event_loop_get_server_fd();
    uint8_t dcid_buffer[MAX_DCID_LEN];
    uint8_t local_dcid_len = 0;

    int local_is_long_header = (is_long_header ? 1 : 0) || ((buffer[0] & 0x80) != 0);
    QuicConnection *conn = NULL;

    if (local_is_long_header) {
        if (core_quic_parser_extract_dcid(buffer, nbytes, dcid_buffer, &local_dcid_len) < 0) {
            if (sock_fd >= 0) {
                sendto(sock_fd, buffer, nbytes, 0, (const struct sockaddr *)client_addr, addr_len);
            }
            return QUIC_FSM_CLOSE_OR_ERR;
        }
    } else {
        /* Short Header (1-RTT): Ambil DCID dengan asumsi panjang DCID standar (8 byte) */
        local_dcid_len = 8;
        if (nbytes > (1 + (size_t)local_dcid_len)) {
            memcpy(dcid_buffer, buffer + 1, local_dcid_len);
        } else {
            return QUIC_FSM_CLOSE_OR_ERR;
        }
    }

    /* Dispatch / cari atau buat koneksi */
    conn = quic_thread_pool_dispatch_connection(dcid_buffer, local_dcid_len, client_addr, addr_len, local_is_long_header);
    if (conn == NULL) {
        return QUIC_FSM_CLOSE_OR_ERR;
    }

    if (conn->sock_server < 0 && sock_fd >= 0) {
        conn->sock_server = sock_fd;
    }

    SSL *ssl = quic_ssl_get_for_conn(conn);
    if (!ssl) {
        return QUIC_FSM_CLOSE_OR_ERR;
    }

    uint8_t decrypted_payload[4096];
    uint8_t tls_record_buf[4096];
    size_t decrypted_len = 0;

    size_t pn_offset = 0, real_packet_len = 0;
    const unsigned char *pkt_dcid_ptr = NULL;
    uint8_t pkt_dcid_len = 0;
    const unsigned char *pkt_scid_ptr = NULL;
    uint8_t pkt_scid_len = 0;
    int pkt_type = 0;
    int decrypt_ok = 0;

    if (!local_is_long_header) {
        /* --- PENANGANAN PAKET 1-RTT (SHORT HEADER) --- */
        if (conn->has_client_app_secret) {
            uint8_t target_dcid_len = (conn->dcid_len > 0) ? conn->dcid_len : local_dcid_len;
            decrypt_ok = quic_handle_1rtt_decryption(
                conn,
                buffer, nbytes,
                conn->client_application_traffic_secret_0,
                target_dcid_len,
                decrypted_payload, &decrypted_len
            );
            fprintf(stderr, "[QUIC 1-RTT IN] Menerima & mendekripsi paket 1-RTT dari klien! Status: %d, Len: %zu\n",
                    decrypt_ok, decrypted_len);
        }
        return decrypt_ok ? QUIC_FSM_ACTIVE_1RTT : QUIC_FSM_NEED_MORE;
    }

    /* --- PENANGANAN LONG HEADER (Initial / Handshake) --- */
    fprintf(stderr, "[QUIC LH CHECK] len=%zu first=0x%02x has_srv_app=%d has_cli_hs=%d\n",
            nbytes,
            (unsigned int)buffer[0],
            conn->has_server_app_secret,
            conn->has_client_hs_secret);

    int hdr_ok = core_quic_parser_parse_packet_header(
        buffer, nbytes, &pn_offset, &real_packet_len,
        &pkt_dcid_ptr, &pkt_dcid_len, &pkt_scid_ptr, &pkt_scid_len, &pkt_type
    );

    fprintf(stderr, "[QUIC HDR DBG] hdr_ok=%d pkt_type=%d pn_off=%zu real_len=%zu dcid_len=%u scid_len=%u\n",
            hdr_ok, pkt_type, pn_offset, real_packet_len,
            (unsigned int)pkt_dcid_len, (unsigned int)pkt_scid_len);

    if (!hdr_ok) {
        return QUIC_FSM_CLOSE_OR_ERR;
    }

    /* Abaikan hanya paket Initial retransmisi jika server sudah masuk fase 1-RTT */
    if (pkt_type == 0 && conn->has_server_app_secret) {
        return QUIC_FSM_ACTIVE_1RTT;
    }

    if (pkt_type == 0) {
        decrypt_ok = quic_handle_decryption(
            buffer, real_packet_len, pn_offset,
            pkt_dcid_ptr, pkt_dcid_len,
            decrypted_payload, &decrypted_len
        );
    } else if (pkt_type == 2) {
        if (!conn->has_client_hs_secret) {
            fprintf(stderr, "[QUIC WARNING] Menerima Handshake packet, tetapi client_hs_secret belum tersedia!\n");
            return QUIC_FSM_NEED_MORE;
        }
        decrypt_ok = quic_handle_handshake_decryption(
            conn,
            buffer, real_packet_len, pn_offset,
            conn->client_handshake_secret,
            decrypted_payload, &decrypted_len
        );
        fprintf(stderr, "[QUIC HANDSHAKE IN] Menerima & mendekripsi paket Handshake dari klien! Status: %d, Len: %zu\n",
                decrypt_ok, decrypted_len);
        if (!decrypt_ok) {
            return QUIC_FSM_NEED_MORE;
        }
    } else {
        return QUIC_FSM_NEED_MORE;
    }

    int is_retransmit = 0;
    if (conn->state == QUIC_STATE_HANDSHAKE && conn->has_sent_initial && pkt_type == 0 && decrypted_len == 0) {
        is_retransmit = 1;
    }

    if (!decrypt_ok) {
        return QUIC_FSM_NEED_MORE;
    }

    if (pkt_type == 2) {
        QuicHandshakeFrameResult fres;
        if (!quic_process_client_handshake_frames(ssl, decrypted_payload, decrypted_len, &fres)) {
            return QUIC_FSM_CLOSE_OR_ERR;
        }

        fprintf(stderr, "[QUIC HS SUMMARY] saw_ack=%d (largest=%llu), saw_crypto=%d (bytes=%zu), tls_done=%d\n",
                fres.saw_ack,
                (unsigned long long)fres.largest_acked_pn,
                fres.saw_crypto,
                fres.crypto_bytes_fed,
                fres.tls_handshake_done);

        if (fres.tls_handshake_done || SSL_is_init_finished(ssl)) {
            conn->state = QUIC_STATE_CONNECTED;
            fprintf(stderr, "[QUIC STATE] Koneksi QUIC BERHASIL TERSAMBUNG (1-RTT Active)!\n");
            return QUIC_FSM_ACTIVE_1RTT;
        }

        if (!fres.saw_crypto || fres.crypto_bytes_fed == 0) {
            if (conn->state == QUIC_STATE_CONNECTED || conn->has_server_app_secret) {
                return QUIC_FSM_ACTIVE_1RTT;
            }
            return QUIC_FSM_NEED_MORE;
        }

        return QUIC_FSM_NEED_MORE;
    }

    /* Jalur pkt_type == 0 (Initial Packet / ClientHello) */
    size_t tls_raw_len = 0;
    const unsigned char *tls_raw_data = core_quic_parser_extract_tls_from_crypto_frame(
        decrypted_payload, decrypted_len, &tls_raw_len
    );

    fprintf(stderr, "[QUIC CRYPTO] Sukses mendekripsi & mengekstrak TLS murni dari paket tipe %d! Len: %zu\n",
            pkt_type, tls_raw_len);

    if (!tls_raw_data || tls_raw_len == 0) {
        if (!is_retransmit) {
            conn->has_sent_initial = 1;
        }
        if (conn->state == QUIC_STATE_CONNECTED || conn->has_server_app_secret) {
            return QUIC_FSM_ACTIVE_1RTT;
        }
        return QUIC_FSM_NEED_MORE;
    }

    if (tls_raw_len + 5 > sizeof(tls_record_buf)) {
        fprintf(stderr, "[QUIC CRYPTO] Ukuran TLS record melebihi buffer (%zu)\n", tls_raw_len);
        return QUIC_FSM_CLOSE_OR_ERR;
    }

    tls_record_buf[0] = 0x16;
    tls_record_buf[1] = 0x03;
    tls_record_buf[2] = 0x03;
    tls_record_buf[3] = (unsigned char)((tls_raw_len >> 8) & 0xFF);
    tls_record_buf[4] = (unsigned char)(tls_raw_len & 0xFF);
    memcpy(tls_record_buf + 5, tls_raw_data, tls_raw_len);

    sec_quic_tls_feed_ssl_and_respond(
        ssl, conn, conn->sock_server,
        tls_record_buf, tls_raw_len + 5,
        pkt_dcid_ptr, pkt_dcid_len,
        pkt_scid_ptr, pkt_scid_len,
        is_retransmit
    );

    if (!is_retransmit) {
        conn->has_sent_initial = 1;
    }

    if (conn->state == QUIC_STATE_CONNECTED || conn->has_server_app_secret) {
        return QUIC_FSM_ACTIVE_1RTT;
    }

    return QUIC_FSM_NEED_MORE;
}

static int quic_spawn_detached_worker(pthread_t *out_tid, void *(*routine)(void *), void *arg) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        return -1;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);

    int ret = pthread_create(out_tid, &attr, routine, arg);
    pthread_attr_destroy(&attr);
    return ret;
}

static void quic_mark_worker_idle(QuicTaskQueue *q) {
    if (q) {
        atomic_fetch_sub(&q->active_workers, 1);
    }
}

void core_quic_thread_pool_start(void) {
    int initial_workers = adaptive_hw_aware.worker_min;
    if (initial_workers < 1) {
        initial_workers = 1;
    }

    for (int i = 0; i < initial_workers; i++) {
        pthread_t tid;
        if (quic_spawn_detached_worker(&tid, core_quic_thread_pool_worker, &quic_global_queue) != 0) {
            write_log("[QUIC THREAD POOL ERROR] Failed to spawn initial worker #%d (errno=%d)", i, errno);
        }
    }
}

void core_quic_thread_pool_stop(void) {
    pthread_mutex_lock(&quic_global_queue.lock);
    atomic_store(&quic_global_queue.is_running, false);
    pthread_cond_broadcast(&quic_global_queue.cond);

    while (quic_global_queue.total_workers > 0) {
        pthread_cond_wait(&quic_global_queue.exit_cond, &quic_global_queue.lock);
    }
    pthread_mutex_unlock(&quic_global_queue.lock);
}

int core_quic_thread_pool_spawn_workers(int count) {
    if (count <= 0) {
        return 0;
    }

    int actually_spawned = 0;
    for (int i = 0; i < count; i++) {
        pthread_t tid;
        if (quic_spawn_detached_worker(&tid, core_quic_thread_pool_worker, &quic_global_queue) == 0) {
            actually_spawned++;
        } else {
            write_log("[QUIC THREAD POOL ERROR] Failed to scale worker (errno=%d)", errno);
        }
    }
    return actually_spawned;
}

void *core_quic_thread_pool_worker(void *arg) {
    QuicTaskQueue *q = (arg != NULL) ? (QuicTaskQueue *)arg : &quic_global_queue;

    while (1) {
        QuicPacketTask task;
        struct timeval arrival;
        memset(&task, 0, sizeof(task));

        int rc = core_quic_queue_pop(q, &task, &arrival);
        if (rc < 0) {
            break;
        }

        if (task.data && task.len > 0) {
            fprintf(stderr, "[QUIC WORKER RX] len=%zu first=0x%02x is_lh=%d has_dcid=%d\n",
                    task.len,
                    (unsigned int)task.data[0],
                    (int)task.is_long_header,
                    (int)task.has_dcid);
        }

        int fsm_status = quic_thread_pool_handle_packet(
            task.data,
            task.len,
            &task.client_addr,
            task.client_addr_len,
            task.dcid,
            task.dcid_len,
            task.has_dcid,
            task.is_long_header
        );

        if (fsm_status == QUIC_FSM_CLOSE_OR_ERR) {
            fprintf(stderr, "[QUIC WORKER] Packet/connection returned CLOSE_OR_ERR (len=%zu)\n",
                    task.len);
        }

        free(task.data);
        quic_mark_worker_idle(q);
    }

    return NULL;
}