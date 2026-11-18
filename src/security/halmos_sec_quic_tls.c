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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

SSL_CTX *halmos_quic_tls_ctx = NULL;

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

                        // --- PICU PENGIRIMAN HTTP/3 SETTINGS OTOMATIS ---
                        quic_send_h3_settings(conn->sock_server, &conn->client_addr, conn->client_addr_len, conn);
                    }
                }
            }
        }
    }
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