#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "halmos_sec_quic_tls.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_core_quic_conn_table.h"
#include "halmos_sec_quic_crypto.h"
#include "halmos_log.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef TLSEXT_TYPE_quic_transport_parameters
#define TLSEXT_TYPE_quic_transport_parameters 0x0039
#endif

SSL_CTX *halmos_quic_tls_ctx = NULL;

static int g_quic_conn_ex_idx = -1;

__attribute__((unused))
static int quic_send_h3_settings(int sock_server, struct sockaddr_in *client_addr, socklen_t client_addr_len, QuicConnection *conn) {
    // Payload HTTP/3 SETTINGS Frame
    // Format HTTP/3 Frame: [Type (Varint), Length (Varint), Payload...]
    // SETTINGS Frame Type = 0x04
    unsigned char h3_payload[64];
    size_t h3_len = 0;

    h3_payload[h3_len++] = 0x04; // HTTP/3 Frame Type: SETTINGS
    h3_payload[h3_len++] = 0x06; // Length of settings payload (6 bytes)
    
    // Setting ID: SETTINGS_MAX_HEADER_LIST_SIZE (0x06) = 16384 (0x40003fff atau varint)
    h3_payload[h3_len++] = 0x06; 
    h3_payload[h3_len++] = 0x04; 
    h3_payload[h3_len++] = 0x40; 
    h3_payload[h3_len++] = 0x00; 
    h3_payload[h3_len++] = 0x3f; 
    h3_payload[h3_len++] = 0xff;

    fprintf(stderr, "[HTTP/3] Menyiapkan pengiriman SETTINGS frame...\n");
    return quic_encrypt_1rtt_packet(sock_server, client_addr, client_addr_len, conn, h3_payload, h3_len);
}

// Callback Keylog OpenSSL yang disempurnakan dengan validasi ketat
static void quic_keylog_callback(const SSL *ssl, const char *line) {
    QuicConnection *conn = (QuicConnection *)SSL_get_app_data(ssl);
    if (!conn) {
        return;
    }

    fprintf(stderr, "[KEYLOG RAW DUMP] %s\n", line);

    // Tangkap Handshake Secret
    if (strncmp(line, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 31) == 0) {
        const char *hex_ptr = line + 32;
        while (*hex_ptr && *hex_ptr != ' ') hex_ptr++;
        if (*hex_ptr == ' ') hex_ptr++;

        unsigned char temp_secret[48];
        int success = 1;
        for (int i = 0; i < 48; i++) {
            unsigned int byte_val = 0;
            if (sscanf(hex_ptr + (i * 2), "%02x", &byte_val) != 1) { success = 0; break; }
            temp_secret[i] = (unsigned char)byte_val;
        }
        if (success) {
            memcpy(conn->client_handshake_secret, temp_secret, 48);
            conn->has_client_hs_secret = 1;
            fprintf(stderr, "[KEYLOG SUCCESS] Client Handshake Secret tersimpan!\n");
        }
    } else if (strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31) == 0) {
        const char *hex_ptr = line + 32;
        while (*hex_ptr && *hex_ptr != ' ') hex_ptr++;
        if (*hex_ptr == ' ') hex_ptr++;

        unsigned char temp_secret[48];
        int success = 1;
        for (int i = 0; i < 48; i++) {
            unsigned int byte_val = 0;
            if (sscanf(hex_ptr + (i * 2), "%02x", &byte_val) != 1) { success = 0; break; }
            temp_secret[i] = (unsigned char)byte_val;
        }
        if (success) {
            memcpy(conn->server_handshake_secret, temp_secret, 48);
            conn->has_server_hs_secret = 1;
            fprintf(stderr, "[KEYLOG SUCCESS] Server Handshake Secret tersimpan!\n");
        }
    } 
    // Tangkap universal TRAFFIC_SECRET_0 (baik client maupun server)
    else if (strstr(line, "TRAFFIC_SECRET_0") != NULL) {
        // Format keylog: LABEL <client_random/secret_id> <secret_hex>
        // Kita cari spasi kedua untuk mendapatkan secret hex terakhir
        const char *first_space = strchr(line, ' ');
        if (first_space) {
            const char *second_space = strchr(first_space + 1, ' ');
            if (second_space) {
                const char *hex_ptr = second_space + 1;
                unsigned char temp_secret[48];
                int success = 1;
                for (int i = 0; i < 48; i++) {
                    unsigned int byte_val = 0;
                    if (sscanf(hex_ptr + (i * 2), "%02x", &byte_val) != 1) { success = 0; break; }
                    temp_secret[i] = (unsigned char)byte_val;
                }
                if (success) {
                    if (strstr(line, "CLIENT") != NULL) {
                        memcpy(conn->client_application_traffic_secret_0, temp_secret, 48);
                        conn->has_client_app_secret = 1;
                        fprintf(stderr, "[KEYLOG SUCCESS] Client Traffic Secret 0 BERHASIL DISIMPAN!\n");
                    } else if (strstr(line, "SERVER") != NULL) {
                        memcpy(conn->server_application_traffic_secret_0, temp_secret, 48);
                        conn->has_server_app_secret = 1;
                        fprintf(stderr, "[KEYLOG SUCCESS] Server Traffic Secret 0 BERHASIL DISIMPAN!\n");
                    }
                }
            }
        }
    }
}

static size_t quic_conn_get_server_scid(
    const QuicConnection *conn,
    unsigned char *out_scid,
    size_t cap
) {
    if (!conn || !out_scid || cap == 0 || conn->server_scid_len == 0) {
        return 0;
    }
    size_t n = (conn->server_scid_len < cap) ? conn->server_scid_len : cap;
    memcpy(out_scid, conn->server_scid, n);
    return n;
}

// Callback pemilihan ALPN khusus server untuk protokol h3
static int quic_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                               const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    // arg berisi daftar protokol yang didukung server (h3)
    const unsigned char *supported_protos = (const unsigned char *)arg;
    unsigned int supported_len = 3; // panjang format wire: [1-byte len][2 bytes 'h3'] atau format kustom

    if (SSL_select_next_proto((unsigned char **)out, outlen, supported_protos, supported_len, in, inlen) 
        != OPENSSL_NPN_NEGOTIATED) {
        // Jika klien tidak mendukung 'h3', tolak koneksi TLS
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static size_t quic_write_varint(unsigned char *dst, uint64_t val) {
    if (val < 64ULL) {
        dst[0] = (unsigned char)val;
        return 1;
    } else if (val < 16384ULL) {
        dst[0] = (unsigned char)(0x40U | ((val >> 8) & 0x3FU));
        dst[1] = (unsigned char)(val & 0xFFU);
        return 2;
    } else if (val < 1073741824ULL) {
        dst[0] = (unsigned char)(0x80U | ((val >> 24) & 0x3FU));
        dst[1] = (unsigned char)((val >> 16) & 0xFFU);
        dst[2] = (unsigned char)((val >> 8) & 0xFFU);
        dst[3] = (unsigned char)(val & 0xFFU);
        return 4;
    } else {
        dst[0] = (unsigned char)(0xC0U | ((val >> 56) & 0x3FU));
        dst[1] = (unsigned char)((val >> 48) & 0xFFU);
        dst[2] = (unsigned char)((val >> 40) & 0xFFU);
        dst[3] = (unsigned char)((val >> 32) & 0xFFU);
        dst[4] = (unsigned char)((val >> 24) & 0xFFU);
        dst[5] = (unsigned char)((val >> 16) & 0xFFU);
        dst[6] = (unsigned char)((val >> 8) & 0xFFU);
        dst[7] = (unsigned char)(val & 0xFFU);
        return 8;
    }
}

// Menulis nilai uint64_t sebagai big-endian minimum bytes (tanpa leading zero).
// Mengembalikan jumlah byte yang ditulis (1..8).
static size_t quic_write_be_uint(unsigned char *dst, uint64_t val) {
    unsigned char tmp[8];
    size_t n = 0;

    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)((val >> (8 * i)) & 0xFFU);
        if (b != 0 || n > 0 || i == 0) {
            tmp[n++] = b;
        }
    }

    memcpy(dst, tmp, n);
    return n;
}

// Menambahkan satu Transport Parameter: [varint id][varint len][value]
static size_t quic_tp_append_uint(
    unsigned char *buf,
    size_t cap,
    size_t pos,
    uint64_t param_id,
    uint64_t val
) {
    unsigned char val_buf[8];
    size_t val_len = quic_write_varint(val_buf, val);

    // Estimasi aman: maksimal 8 + 8 + 8 = 24 byte
    if (pos + 24 > cap || val_len == 0) {
        fprintf(stderr, "[QUIC TP PARAM DBG] SKIP param_id=0x%llx (pos=%zu + 24 > cap=%zu)\n",
                (unsigned long long)param_id, pos, cap);
        return pos;
    }

    size_t start_pos = pos;
    pos += quic_write_varint(buf + pos, param_id);
    pos += quic_write_varint(buf + pos, (uint64_t)val_len);
    memcpy(buf + pos, val_buf, val_len);
    pos += val_len;

    fprintf(stderr, "[QUIC TP PARAM DBG] id=0x%llx val=%llu varint_len=%zu added=%zu hex=",
            (unsigned long long)param_id,
            (unsigned long long)val,
            val_len,
            pos - start_pos);
    for (size_t i = start_pos; i < pos; i++) {
        fprintf(stderr, "%02x%s", buf[i], (i + 1 < pos) ? " " : "");
    }
    fprintf(stderr, "\n");

    return pos;
}

static size_t quic_tp_append_bytes(
    unsigned char *buf,
    size_t cap,
    size_t pos,
    uint64_t param_id,
    const unsigned char *data,
    size_t data_len
) {
    if (!data && data_len > 0) {
        return pos;
    }
    if (pos + 16 + data_len > cap) {
        return pos;
    }

    pos += quic_write_varint(buf + pos, param_id);
    pos += quic_write_varint(buf + pos, (uint64_t)data_len);
    if (data_len > 0) {
        memcpy(buf + pos, data, data_len);
        pos += data_len;
    }
    return pos;
}

// Menyusun seluruh Transport Parameters server ke dalam out_buf.
// Mengembalikan panjang total byte yang ditulis.
static size_t quic_build_server_transport_params(
    unsigned char *out_buf,
    size_t cap,
    const unsigned char *orig_dcid,
    size_t orig_dcid_len,
    const unsigned char *initial_scid,
    size_t initial_scid_len
) {
    size_t pos = 0;

    if (orig_dcid && orig_dcid_len > 0) {
        size_t start_pos = pos;
        pos = quic_tp_append_bytes(out_buf, cap, pos, 0x00ULL, orig_dcid, orig_dcid_len);
        fprintf(stderr, "[QUIC TP PARAM DBG] id=0x0 len=%zu added=%zu hex=",
                orig_dcid_len, pos - start_pos);
        for (size_t i = start_pos; i < pos; i++) {
            fprintf(stderr, "%02x%s", out_buf[i], (i + 1 < pos) ? " " : "");
        }
        fprintf(stderr, "\n");
    }

    pos = quic_tp_append_uint(out_buf, cap, pos, 0x03ULL, 1452ULL);   // max_udp_payload_size
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x04ULL, 1048576ULL); // initial_max_data
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x05ULL, 262144ULL); // initial_max_stream_data_bidi_local
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x06ULL, 262144ULL); // initial_max_stream_data_bidi_remote
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x07ULL, 262144ULL); // initial_max_stream_data_uni
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x08ULL, 100ULL);    // initial_max_streams_bidi
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x09ULL, 100ULL);    // initial_max_streams_uni
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x0aULL, 3ULL);      // ack_delay_exponent
    pos = quic_tp_append_uint(out_buf, cap, pos, 0x0bULL, 25ULL);     // max_ack_delay

    if (initial_scid && initial_scid_len > 0) {
        size_t start_pos = pos;
        pos = quic_tp_append_bytes(out_buf, cap, pos, 0x0fULL, initial_scid, initial_scid_len);
        fprintf(stderr, "[QUIC TP PARAM DBG] id=0xf len=%zu added=%zu hex=",
                initial_scid_len, pos - start_pos);
        for (size_t i = start_pos; i < pos; i++) {
            fprintf(stderr, "%02x%s", out_buf[i], (i + 1 < pos) ? " " : "");
        }
        fprintf(stderr, "\n");
    }

    return pos;
}

static int quic_tp_add_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *add_arg
) {
    (void)ext_type;
    (void)context;
    (void)x;
    (void)chainidx;
    (void)al;
    (void)add_arg;

    unsigned char *tp_buf = OPENSSL_malloc(256);
    if (!tp_buf) {
        return -1;
    }

    unsigned char orig_dcid_buf[64];
    size_t orig_dcid_len = 0;
    unsigned char scid_buf[64];
    size_t scid_len = 0;

    if (ssl) {
        QuicConnection *conn = NULL;
        if (g_quic_conn_ex_idx >= 0) {
            conn = (QuicConnection *)SSL_get_ex_data(ssl, g_quic_conn_ex_idx);
        }
        if (!conn) {
            conn = (QuicConnection *)SSL_get_app_data(ssl);
        }
        if (conn) {
            if (conn->orig_dcid_len > 0) {
                size_t copy_len = (conn->orig_dcid_len < sizeof(orig_dcid_buf))
                                      ? conn->orig_dcid_len
                                      : sizeof(orig_dcid_buf);
                memcpy(orig_dcid_buf, conn->orig_dcid, copy_len);
                orig_dcid_len = copy_len;
            }
            scid_len = quic_conn_get_server_scid(conn, scid_buf, sizeof(scid_buf));
        }
    }

    size_t tp_len = quic_build_server_transport_params(
        tp_buf,
        256,
        orig_dcid_buf,
        orig_dcid_len,
        scid_buf,
        scid_len
    );
    if (tp_len == 0) {
        OPENSSL_free(tp_buf);
        return -1;
    }

    fprintf(stderr, "[QUIC TP] tp_len=%zu, orig_dcid_len=%zu, scid_len=%zu, hex=",
            tp_len, orig_dcid_len, scid_len);
    for (size_t i = 0; i < tp_len; i++) {
        fprintf(stderr, "%02x%s", tp_buf[i], (i + 1 < tp_len) ? " " : "");
    }
    fprintf(stderr, "\n");

    *out = tp_buf;
    *outlen = tp_len;
    return 1;
}

static void quic_tp_free_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *out,
    void *add_arg
) {
    (void)ssl;
    (void)ext_type;
    (void)context;
    (void)add_arg;

    if (out) {
        OPENSSL_free((void *)out);
    }
}

static int quic_tp_parse_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *parse_arg
) {
    (void)ssl;
    (void)ext_type;
    (void)context;
    (void)in;
    (void)inlen;
    (void)x;
    (void)chainidx;
    (void)al;
    (void)parse_arg;

    return 1;
}

int quic_ssl_init(void) {
    if (!config.tls_enabled) return 0;

    const SSL_METHOD *method = TLS_server_method();
    if (!method) {
        write_log_error_code(ERR_SEC_SSL_CTX, "Failed to load TLS_server_method()");
        return -1;
    }

    halmos_quic_tls_ctx = SSL_CTX_new(method);
    if (!halmos_quic_tls_ctx) {
        write_log_error_code(ERR_SEC_SSL_CTX, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // QUIC wajib menggunakan TLS 1.3 murni
    SSL_CTX_set_min_proto_version(halmos_quic_tls_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(halmos_quic_tls_ctx, TLS1_3_VERSION);

     // Daftarkan Keylog Callback untuk menangkap traffic secret
    SSL_CTX_set_keylog_callback(halmos_quic_tls_ctx, quic_keylog_callback);

    // Wire format ALPN untuk h3: [length byte (2)] + ['h', '3']
    static unsigned char quic_protos[] = {
        2, 'h', '3'
    };

    // PERBAIKAN: Sisi server HANYA menggunakan SSL_CTX_set_alpn_select_cb, bukan set_alpn_protos
    SSL_CTX_set_alpn_select_cb(halmos_quic_tls_ctx, quic_alpn_select_cb, quic_protos);

    if (SSL_CTX_use_certificate_chain_file(halmos_quic_tls_ctx, config.ssl_certificate_file) <= 0) {
        write_log_error_code(ERR_SEC_LOAD_CERT, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(halmos_quic_tls_ctx);
        halmos_quic_tls_ctx = NULL;
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(halmos_quic_tls_ctx, config.ssl_private_key_file, SSL_FILETYPE_PEM) <= 0) {
        write_log_error_code(ERR_SEC_LOAD_KEY, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(halmos_quic_tls_ctx);
        halmos_quic_tls_ctx = NULL;
        return -1;
    }

    // Daftarkan QUIC Transport Parameters (extension 0x0039) untuk EncryptedExtensions
    if (SSL_CTX_add_custom_ext(
            halmos_quic_tls_ctx,
            TLSEXT_TYPE_quic_transport_parameters,
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
            quic_tp_add_cb,
            quic_tp_free_cb,
            NULL,
            quic_tp_parse_cb,
            NULL
        ) <= 0) {
        write_log_error_code(ERR_SEC_SSL_CTX, "Failed to register QUIC transport parameters extension");
        SSL_CTX_free(halmos_quic_tls_ctx);
        halmos_quic_tls_ctx = NULL;
        return -1;
    }

    if (g_quic_conn_ex_idx < 0) {
        g_quic_conn_ex_idx = SSL_get_ex_new_index(0, "Halmos QuicConnection", NULL, NULL, NULL);
        if (g_quic_conn_ex_idx < 0) {
            write_log_error_code(ERR_SEC_SSL_CTX, "Failed to allocate SSL ex_data index for QuicConnection");
            SSL_CTX_free(halmos_quic_tls_ctx);
            halmos_quic_tls_ctx = NULL;
            return -1;
        }
    }
    
    write_log("[SEC QUIC] OpenSSL 3.0.22 TLS Engine for QUIC initialized successfully.");
    return 0;
}

void quic_ssl_cleanup(void) {
    if (halmos_quic_tls_ctx == NULL) return;

    SSL_CTX_free(halmos_quic_tls_ctx);
    halmos_quic_tls_ctx = NULL;

    write_log("[SEC QUIC] QUIC TLS Engine resources cleaned up.");
}

void quic_ssl_set_for_conn(void *conn_ptr, SSL *ssl) {
    QuicConnection *conn = (QuicConnection *)conn_ptr;
    if (!conn) return;
    conn->ssl_quic_ctx = ssl;
}

SSL* quic_ssl_get_for_conn(void *conn_ptr) {
    QuicConnection *conn = (QuicConnection *)conn_ptr;
    if (!conn) return NULL;
    return conn->ssl_quic_ctx;
}

void quic_ssl_free_for_conn(void *conn_ptr) {
    QuicConnection *conn = (QuicConnection *)conn_ptr;
    if (!conn) return;

    SSL *ssl_to_free = conn->ssl_quic_ctx;
    conn->ssl_quic_ctx = NULL;

    if (ssl_to_free) {
        // PERBAIKAN: QUIC tidak menggunakan TLS close_notify / SSL_shutdown, langsung bebaskan objek SSL
        SSL_free(ssl_to_free);
    }
}

static // Fungsi helper terpusat untuk mencetak hex dump outbound
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

// Helper: dekripsi TLS 1.3 record 0x17 (Handshake) menggunakan server_handshake_secret
// Mengembalikan panjang plaintext handshake murni (tanpa inner content type), atau 0 jika gagal.
static size_t quic_decrypt_tls13_hs_record(
    const unsigned char *hs_secret,
    int use_aes_256,
    uint64_t tls_seq_num,
    const unsigned char *tls_hdr5,
    const unsigned char *enc_payload,
    size_t enc_len,
    unsigned char *out_plain,
    size_t out_cap
) {
    if (!hs_secret || !tls_hdr5 || !enc_payload || enc_len < 17 || !out_plain || out_cap == 0) {
        return 0;
    }

    static unsigned char raw_inner[16384];
    size_t tag_len = 16;
    size_t ct_len = enc_len - tag_len;
    if (ct_len == 0 || ct_len > out_cap || ct_len > sizeof(raw_inner)) {
        return 0;
    }

    size_t key_len = use_aes_256 ? 32 : 16;
    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    unsigned char nonce[12] = {0};
    unsigned char tag_copy[16];

    if (!quic_hkdf_expand_label_sha384(hs_secret, "key", NULL, 0, key, key_len) ||
        !quic_hkdf_expand_label_sha384(hs_secret, "iv", NULL, 0, iv, 12)) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return 0;
    }

    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= (unsigned char)((tls_seq_num >> (8 * i)) & 0xFF);
    }

    memcpy(tag_copy, enc_payload + ct_len, tag_len);

    const EVP_CIPHER *cipher = use_aes_256 ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return 0;
    }

    int out_len = 0;
    int plain_total = 0;

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) ||
        !EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) ||
        !EVP_DecryptUpdate(ctx, NULL, &out_len, tls_hdr5, 5) ||
        !EVP_DecryptUpdate(ctx, raw_inner, &out_len, enc_payload, (int)ct_len)) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return 0;
    }
    plain_total = out_len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, tag_copy) ||
        EVP_DecryptFinal_ex(ctx, raw_inner + plain_total, &out_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return 0;
    }
    plain_total += out_len;
    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));

    if (plain_total <= 0 || (size_t)plain_total > sizeof(raw_inner)) {
        return 0;
    }

    // Buang trailing zero padding TLS 1.3 untuk menemukan InnerContentType
    int idx = plain_total - 1;
    while (idx >= 0 && raw_inner[idx] == 0x00) {
        idx--;
    }
    if (idx < 0) {
        return 0;
    }

    uint8_t inner_type = raw_inner[idx];
    size_t hs_plain_len = (size_t)idx;
    if (inner_type != 0x16 || hs_plain_len == 0 || hs_plain_len > out_cap) {
        return 0;
    }

    memcpy(out_plain, raw_inner, hs_plain_len);
    return hs_plain_len;
}

// ================== GROUP sec_quic_tls_feed_ssl_and_respond =============================
static const char *quic_cipher_suite_to_str(QuicCipherSuite suite) {
    switch (suite) {
        case QUIC_CIPHER_AES_128_GCM_SHA256:
            return "QUIC_CIPHER_AES_128_GCM_SHA256";
        case QUIC_CIPHER_AES_256_GCM_SHA384:
            return "QUIC_CIPHER_AES_256_GCM_SHA384";
        case QUIC_CIPHER_CHACHA20_POLY1305:
            return "QUIC_CIPHER_CHACHA20_POLY1305";
        case QUIC_CIPHER_UNKNOWN:
        default:
            return "QUIC_CIPHER_UNKNOWN";
    }
}

static QuicCipherSuite quic_tls_detect_and_store_cipher(SSL *ssl, QuicConnection *conn) {
    if (!ssl) {
        QuicCipherSuite fallback = (conn && conn->cipher_suite != QUIC_CIPHER_UNKNOWN)
                                     ? conn->cipher_suite
                                     : QUIC_CIPHER_UNKNOWN;
        fprintf(stderr, "[QUIC TLS DEBUG] ssl is NULL -> returning %s (%d)\n",
                quic_cipher_suite_to_str(fallback), (int)fallback);
        return fallback;
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (!cipher) {
        QuicCipherSuite fallback = (conn && conn->cipher_suite != QUIC_CIPHER_UNKNOWN)
                                     ? conn->cipher_suite
                                     : QUIC_CIPHER_UNKNOWN;
        fprintf(stderr, "[QUIC TLS DEBUG] SSL_get_current_cipher is NULL (handshake belum selesai?) -> returning %s (%d)\n",
                quic_cipher_suite_to_str(fallback), (int)fallback);
        return fallback;
    }

    QuicCipherSuite detected = QUIC_CIPHER_UNKNOWN;
    size_t key_len = 0;
    size_t secret_len = 0;

    const char *cipher_name = SSL_CIPHER_get_name(cipher);
    uint32_t cipher_id = SSL_CIPHER_get_id(cipher) & 0xFFFFU;

    if (cipher_name) {
        if (strstr(cipher_name, "AES_256_GCM") != NULL || strstr(cipher_name, "256") != NULL) {
            detected = QUIC_CIPHER_AES_256_GCM_SHA384;
            key_len = 32;
            secret_len = 48;
        } else if (strstr(cipher_name, "CHACHA20_POLY1305") != NULL || strstr(cipher_name, "CHACHA20") != NULL) {
            detected = QUIC_CIPHER_CHACHA20_POLY1305;
            key_len = 32;
            secret_len = 32;
        } else if (strstr(cipher_name, "AES_128_GCM") != NULL || strstr(cipher_name, "128") != NULL) {
            detected = QUIC_CIPHER_AES_128_GCM_SHA256;
            key_len = 16;
            secret_len = 32;
        }
    }

    if (detected == QUIC_CIPHER_UNKNOWN) {
        /* Cadangan berdasarkan cipher ID TLS 1.3 jika nama tidak cocok pola string */
        if (cipher_id == 0x1302U) { /* TLS_AES_256_GCM_SHA384 */
            detected = QUIC_CIPHER_AES_256_GCM_SHA384;
            key_len = 32;
            secret_len = 48;
        } else if (cipher_id == 0x1303U) { /* TLS_CHACHA20_POLY1305_SHA256 */
            detected = QUIC_CIPHER_CHACHA20_POLY1305;
            key_len = 32;
            secret_len = 32;
        } else if (cipher_id == 0x1301U) { /* TLS_AES_128_GCM_SHA256 */
            detected = QUIC_CIPHER_AES_128_GCM_SHA256;
            key_len = 16;
            secret_len = 32;
        }
    }

    QuicCipherSuite result = (detected != QUIC_CIPHER_UNKNOWN)
                               ? detected
                               : ((conn) ? conn->cipher_suite : QUIC_CIPHER_UNKNOWN);

    fprintf(stderr,
            "[QUIC TLS DEBUG] conn=%p openssl_name=\"%s\" id=0x%04x detected=%s (%d) key_len=%zu secret_len=%zu final=%s\n",
            (void *)conn,
            cipher_name ? cipher_name : "(null)",
            cipher_id,
            quic_cipher_suite_to_str(detected),
            (int)detected,
            key_len,
            secret_len,
            quic_cipher_suite_to_str(result));

    if (conn && detected != QUIC_CIPHER_UNKNOWN) {
        conn->cipher_suite = detected;
        conn->aead_key_len = key_len;
        conn->secret_len = secret_len;
    }

    return result;
}

static void quic_tls_handle_retransmit(
    QuicConnection *conn,
    int sock_server
) {
    if (conn && conn->has_cached_response) {
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
}

QuicCipherSuite quic_tls_feed_incoming_bytes(
    SSL *ssl,
    QuicConnection *conn,
    const unsigned char *feed_buffer,
    size_t feed_len,
    const unsigned char *client_dcid,
    size_t client_dcid_len
) {
    if (!ssl) {
        return QUIC_CIPHER_UNKNOWN;
    }

    if (feed_buffer && feed_len > 0) {
        if (conn && conn->orig_dcid_len == 0 && client_dcid && client_dcid_len > 0) {
            size_t copy_len = (client_dcid_len < sizeof(conn->orig_dcid))
                                  ? client_dcid_len
                                  : sizeof(conn->orig_dcid);
            memcpy(conn->orig_dcid, client_dcid, copy_len);
            conn->orig_dcid_len = copy_len;
            fprintf(stderr, "[QUIC ORIG DCID] conn=%p, orig_dcid_len=%zu\n",
                    (void *)conn, conn->orig_dcid_len);
        }

        if (conn && conn->server_scid_len == 0 && client_dcid && client_dcid_len > 0) {
            quic_conn_set_server_scid(conn, client_dcid, client_dcid_len);
            fprintf(stderr, "[QUIC SCID PRE-SET] conn=%p, server_scid_len=%zu\n",
                    (void *)conn, conn->server_scid_len);
        }

        BIO *rbio = SSL_get_rbio(ssl);
        if (!rbio) {
            rbio = BIO_new(BIO_s_mem());
            BIO *wbio = BIO_new(BIO_s_mem());
            if (!rbio || !wbio) {
                if (rbio) {
                    BIO_free(rbio);
                }
                if (wbio) {
                    BIO_free(wbio);
                }
                fprintf(stderr, "[QUIC SSL ERROR] Gagal mengalokasikan BIO memori\n");
                return QUIC_CIPHER_UNKNOWN;
            }
            SSL_set_bio(ssl, rbio, wbio);
        }

        int has_tls_hdr = (feed_len >= 5 && feed_buffer[0] == 0x16 && feed_buffer[1] == 0x03);
        if (!has_tls_hdr) {
            if (feed_len > 0xFFFFU || feed_len > (size_t)INT_MAX) {
                fprintf(stderr, "[QUIC SSL ERROR] Panjang feed_buffer di luar batas record: %zu\n", feed_len);
                return QUIC_CIPHER_UNKNOWN;
            }
            unsigned char hdr[5];
            hdr[0] = 0x16;
            hdr[1] = 0x03;
            hdr[2] = 0x03;
            hdr[3] = (unsigned char)((feed_len >> 8) & 0xFF);
            hdr[4] = (unsigned char)(feed_len & 0xFF);
            int w_hdr = BIO_write(rbio, hdr, 5);
            if (w_hdr != 5) {
                fprintf(stderr, "[QUIC SSL ERROR] BIO_write header gagal (w_hdr=%d)\n", w_hdr);
                return QUIC_CIPHER_UNKNOWN;
            }
        }

        if (feed_len > (size_t)INT_MAX) {
            fprintf(stderr, "[QUIC SSL ERROR] feed_len terlalu besar: %zu\n", feed_len);
            return QUIC_CIPHER_UNKNOWN;
        }
        int w_body = BIO_write(rbio, feed_buffer, (int)feed_len);
        if (w_body != (int)feed_len) {
            fprintf(stderr, "[QUIC SSL ERROR] BIO_write tidak lengkap (w_body=%d, expected=%zu)\n",
                    w_body, feed_len);
            return QUIC_CIPHER_UNKNOWN;
        }

        fprintf(stderr, "[QUIC CH STATE] sebelum SSL_accept: %s\n", SSL_state_string_long(ssl));
        int ret = SSL_accept(ssl);
        fprintf(stderr, "[QUIC CH STATE] sesudah SSL_accept (ret=%d): %s\n",
                ret, SSL_state_string_long(ssl));
        if (ret <= 0) {
            int ssl_err = SSL_get_error(ssl, ret);
            if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
                unsigned long err_code = ERR_get_error();
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                fprintf(stderr, "[QUIC SSL ERROR] OpenSSL error (ssl_err=%d): %s\n", ssl_err, err_buf);
                return QUIC_CIPHER_UNKNOWN;
            }
        }
    }

    return quic_tls_detect_and_store_cipher(ssl, conn);
}

static void quic_tls_send_server_initial_from_sh(
    QuicConnection *conn,
    int sock_server,
    const unsigned char *record_payload,
    size_t total_server_hello_len,
    const unsigned char *client_dcid,
    size_t client_dcid_len,
    const unsigned char *client_scid,
    size_t client_scid_len
) {
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
            record_payload, total_server_hello_len,
            assembled_plaintext
        );

        const unsigned char *srv_scid = (conn && conn->server_scid_len > 0) ? conn->server_scid : client_dcid;
        size_t srv_scid_len = (conn && conn->server_scid_len > 0) ? conn->server_scid_len : client_dcid_len;

        if (quic_encrypt_server_initial(
            conn,
            assembled_plaintext, assembled_len,
            client_scid, client_scid_len,
            srv_scid, srv_scid_len,
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
}

static void quic_tls_encrypt_and_send_hs_frame(
    QuicConnection *conn,
    int sock_server,
    const unsigned char *tls_plain,
    size_t tls_plain_len,
    const unsigned char *client_dcid,
    size_t client_dcid_len,
    const unsigned char *client_scid,
    size_t client_scid_len,
    size_t key_len,
    const EVP_CIPHER *aead_cipher,
    const EVP_CIPHER *hp_cipher,
    int save_to_cache,
    const char *dump_label
) {
    if (!conn || !conn->has_server_hs_secret || !tls_plain || tls_plain_len == 0) {
        return;
    }

    uint64_t cf_offset = conn->handshake_crypto_offset;
    unsigned char hs_crypto_frame[16384];
    size_t hs_cf_pos = 0;

    hs_crypto_frame[hs_cf_pos++] = 0x06;
    hs_cf_pos += quic_write_varint(hs_crypto_frame + hs_cf_pos, cf_offset);
    hs_cf_pos += quic_write_varint(hs_crypto_frame + hs_cf_pos, (uint64_t)tls_plain_len);

    if (hs_cf_pos + tls_plain_len > sizeof(hs_crypto_frame)) {
        return;
    }
    memcpy(hs_crypto_frame + hs_cf_pos, tls_plain, tls_plain_len);
    hs_cf_pos += tls_plain_len;

    unsigned char hs_packet_out[16384];
    size_t hs_pkt_pos = 0;

    hs_packet_out[hs_pkt_pos++] = 0xE0;
    hs_packet_out[hs_pkt_pos++] = 0x00;
    hs_packet_out[hs_pkt_pos++] = 0x00;
    hs_packet_out[hs_pkt_pos++] = 0x00;
    hs_packet_out[hs_pkt_pos++] = 0x01;

    hs_packet_out[hs_pkt_pos++] = (unsigned char)client_scid_len;
    if (client_scid_len > 0 && client_scid) {
        memcpy(hs_packet_out + hs_pkt_pos, client_scid, client_scid_len);
        hs_pkt_pos += client_scid_len;
    }

    hs_packet_out[hs_pkt_pos++] = (unsigned char)client_dcid_len;
    if (client_dcid_len > 0 && client_dcid) {
        memcpy(hs_packet_out + hs_pkt_pos, client_dcid, client_dcid_len);
        hs_pkt_pos += client_dcid_len;
    }

    size_t hs_tag_len = 16;
    size_t hs_remaining_len = 1 + hs_cf_pos + hs_tag_len;
    hs_pkt_pos += quic_write_varint(hs_packet_out + hs_pkt_pos, (uint64_t)hs_remaining_len);

    size_t hs_pn_offset = hs_pkt_pos;
    hs_packet_out[hs_pkt_pos++] = (unsigned char)(conn->next_handshake_packet_number & 0xFF);

    size_t hs_aad_len = hs_pkt_pos;
    const unsigned char *hs_aad = hs_packet_out;

    unsigned char hs_key[32], hs_iv[12], hs_hp[32];
    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic key", NULL, 0, hs_key, key_len);
    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic iv", NULL, 0, hs_iv, 12);
    quic_hkdf_expand_label_sha384(conn->server_handshake_secret, "quic hp", NULL, 0, hs_hp, key_len);

    unsigned char hs_nonce[12];
    memcpy(hs_nonce, hs_iv, 12);
    for (size_t k = 0; k < 8; k++) {
        hs_nonce[11 - k] ^= (unsigned char)((conn->next_handshake_packet_number >> (8 * k)) & 0xFF);
    }

    EVP_CIPHER_CTX *hs_ctx = EVP_CIPHER_CTX_new();
    if (!hs_ctx) {
        return;
    }

    int len = 0, ct_len = 0;
    unsigned char *ct_dest = hs_packet_out + hs_pkt_pos;

    if (hs_pkt_pos + hs_cf_pos + hs_tag_len <= sizeof(hs_packet_out) &&
        EVP_EncryptInit_ex(hs_ctx, aead_cipher, NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
        EVP_EncryptInit_ex(hs_ctx, NULL, NULL, hs_key, hs_nonce) &&
        EVP_EncryptUpdate(hs_ctx, NULL, &len, hs_aad, (int)hs_aad_len) &&
        EVP_EncryptUpdate(hs_ctx, ct_dest, &len, hs_crypto_frame, (int)hs_cf_pos)) {

        ct_len = len;
        hs_pkt_pos += (size_t)ct_len;

        unsigned char hs_tag[16];
        if (EVP_EncryptFinal_ex(hs_ctx, ct_dest + ct_len, &len) &&
            EVP_CIPHER_CTX_ctrl(hs_ctx, EVP_CTRL_GCM_GET_TAG, 16, hs_tag)) {

            memcpy(ct_dest + ct_len, hs_tag, 16);
            hs_pkt_pos += 16;

            size_t sample_off = hs_pn_offset + 4;
            if (sample_off + 16 <= hs_pkt_pos) {
                unsigned char sample[16];
                memcpy(sample, hs_packet_out + sample_off, 16);

                unsigned char mask[16];
                int outlen = 0;
                EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
                if (hp_ctx) {
                    if (EVP_EncryptInit_ex(hp_ctx, hp_cipher, NULL, hs_hp, NULL)) {
                        EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
                        EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);

                        hs_packet_out[0] ^= (mask[0] & 0x0f);
                        hs_packet_out[hs_pn_offset] ^= mask[1];
                    }
                    EVP_CIPHER_CTX_free(hp_ctx);
                }

                if (dump_label) {
                    print_outbound_hex_dump(dump_label, hs_packet_out, hs_pkt_pos, hs_pn_offset);
                }

                sendto(sock_server, hs_packet_out, hs_pkt_pos, 0,
                       (const struct sockaddr *)&conn->client_addr, conn->client_addr_len);

                conn->next_handshake_packet_number++;
                conn->handshake_crypto_offset += (uint64_t)tls_plain_len;

                if (save_to_cache && hs_pkt_pos <= sizeof(conn->handshake_cache)) {
                    memcpy(conn->handshake_cache, hs_packet_out, hs_pkt_pos);
                    conn->handshake_cache_len = hs_pkt_pos;
                }

                fprintf(stderr, "[QUIC MTU] Sukses mengirim Handshake Packet (%zu bytes, offset=%llu, key_len=%zu)\n",
                        hs_pkt_pos, (unsigned long long)cf_offset, key_len);
            }
        }
    }

    EVP_CIPHER_CTX_free(hs_ctx);
}

static void quic_tls_process_wbio_records(
    SSL *ssl,
    QuicConnection *conn,
    int sock_server,
    const unsigned char *client_dcid,
    size_t client_dcid_len,
    const unsigned char *client_scid,
    size_t client_scid_len,
    size_t key_len,
    int use_aes_256,
    const EVP_CIPHER *aead_cipher,
    const EVP_CIPHER *hp_cipher
) {
    BIO *wbio = SSL_get_wbio(ssl);
    if (!wbio) {
        return;
    }

    while (BIO_pending(wbio) >= 5) {
        unsigned char header[5];
        if (BIO_read(wbio, header, 5) != 5) break;

        uint8_t record_type = header[0];
        size_t record_len = ((size_t)header[3] << 8) | (size_t)header[4];

        if (record_len > 8192) break;

        unsigned char record_payload[8192];
        if ((size_t)BIO_read(wbio, record_payload, record_len) != record_len) break;

        fprintf(stderr, "[QUIC TLS RECORD] Type: 0x%02x, Len: %zu\n", record_type, record_len);

        if (record_type == 0x16) {
            if (record_payload[0] == 0x02) {
                size_t sh_len = ((size_t)record_payload[1] << 16) |
                                ((size_t)record_payload[2] << 8) |
                                ((size_t)record_payload[3]);
                size_t total_server_hello_len = 4 + sh_len;

                quic_tls_send_server_initial_from_sh(
                    conn, sock_server, record_payload, total_server_hello_len,
                    client_dcid, client_dcid_len, client_scid, client_scid_len
                );

                if (record_len > total_server_hello_len) {
                    if (!conn->has_server_hs_secret) {
                        fprintf(stderr, "[QUIC INFO] Server Handshake Secret belum tersedia. Menunda sisa handshake...\n");
                        break;
                    }
                    quic_tls_encrypt_and_send_hs_frame(
                        conn, sock_server,
                        record_payload + total_server_hello_len,
                        record_len - total_server_hello_len,
                        client_dcid, client_dcid_len, client_scid, client_scid_len,
                        key_len, aead_cipher, hp_cipher, 1, "INIT_FIRST_SEND"
                    );
                }
            } else if (conn->has_server_hs_secret) {
                quic_tls_encrypt_and_send_hs_frame(
                    conn, sock_server, record_payload, record_len,
                    client_dcid, client_dcid_len, client_scid, client_scid_len,
                    key_len, aead_cipher, hp_cipher, 0, NULL
                );
            }
        } else if (record_type == 0x17) {
            if (conn->has_server_hs_secret && record_len > 0) {
                static unsigned char hs_plain[16384];

                size_t hs_plain_len = quic_decrypt_tls13_hs_record(
                    conn->server_handshake_secret,
                    use_aes_256,
                    conn->tls_hs_seq_num,
                    header,
                    record_payload,
                    record_len,
                    hs_plain,
                    sizeof(hs_plain)
                );

                if (hs_plain_len == 0) {
                    fprintf(stderr, "[QUIC TLS WARN] Gagal mendekripsi record 0x17 (seq=%llu, rec_len=%zu)\n",
                            (unsigned long long)conn->tls_hs_seq_num, record_len);
                    break;
                }
                conn->tls_hs_seq_num++;

                if (hs_plain_len >= 4) {
                    uint8_t hs_type = hs_plain[0];
                    size_t hs_msg_len = ((size_t)hs_plain[1] << 16) |
                                      ((size_t)hs_plain[2] << 8) |
                                      ((size_t)hs_plain[3]);
                    fprintf(stderr, "[QUIC HS MSG] plain_len=%zu, hs_type=0x%02x (%u), hs_msg_len=%zu, first4=%02x %02x %02x %02x\n",
                            hs_plain_len, hs_type, (unsigned int)hs_type, hs_msg_len,
                            hs_plain[0], hs_plain[1], hs_plain[2], hs_plain[3]);
                    if (hs_type == 0x08) {
                        fprintf(stderr, "[QUIC EE HEX] ");
                        for (size_t b = 0; b < hs_plain_len; b++) {
                            fprintf(stderr, "%02x%s", hs_plain[b], (b + 1 < hs_plain_len) ? " " : "");
                        }
                        fprintf(stderr, "\n");
                    }
                }

                quic_tls_encrypt_and_send_hs_frame(
                    conn, sock_server, hs_plain, hs_plain_len,
                    client_dcid, client_dcid_len, client_scid, client_scid_len,
                    key_len, aead_cipher, hp_cipher, 0, NULL
                );
            }
        }
    }
}

void sec_quic_tls_feed_ssl_and_respond(SSL *ssl, QuicConnection *conn, int sock_server,
                                       const unsigned char *feed_buffer, size_t feed_len,
                                       const unsigned char *client_dcid, size_t client_dcid_len,
                                       const unsigned char *client_scid, size_t client_scid_len,
                                       int is_retransmit) {
    if (is_retransmit && !feed_len) {
        quic_tls_handle_retransmit(conn, sock_server);
        return;
    }

    QuicCipherSuite active_cipher = quic_tls_feed_incoming_bytes(
        ssl, conn, feed_buffer, feed_len, client_dcid, client_dcid_len
    );

    size_t key_len = (conn && conn->aead_key_len > 0)
                         ? conn->aead_key_len
                         : ((active_cipher == QUIC_CIPHER_AES_256_GCM_SHA384 ||
                             active_cipher == QUIC_CIPHER_CHACHA20_POLY1305) ? 32 : 16);
    int use_aes_256 = (key_len == 32) ? 1 : 0;
    const EVP_CIPHER *aead_cipher = (key_len == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    const EVP_CIPHER *hp_cipher   = (key_len == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();

    quic_tls_process_wbio_records(
        ssl, conn, sock_server,
        client_dcid, client_dcid_len, client_scid, client_scid_len,
        key_len, use_aes_256, aead_cipher, hp_cipher
    );
}
