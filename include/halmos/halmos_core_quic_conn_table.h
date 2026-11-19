#ifndef HALMOS_CORE_QUIC_CONN_TABLE_H
#define HALMOS_CORE_QUIC_CONN_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>

#define MAX_DCID_LEN 20

typedef enum {
    QUIC_STATE_HANDSHAKE = 0,
    QUIC_STATE_CONNECTED,
    QUIC_STATE_CLOSING,
    QUIC_STATE_DEAD
} QuicConnectionState;

typedef enum {
    QUIC_CIPHER_UNKNOWN = 0,          /* Belum terdeteksi atau belum dinegosiasikan */
    QUIC_CIPHER_AES_128_GCM_SHA256,   /* Kunci 16B, IV 12B, HP AES-128-ECB, HKDF SHA-256 */
    QUIC_CIPHER_AES_256_GCM_SHA384,   /* Kunci 32B, IV 12B, HP AES-256-ECB, HKDF SHA-384 */
    QUIC_CIPHER_CHACHA20_POLY1305,    /* Kunci 32B, IV 12B, HP ChaCha20, HKDF SHA-256 */
    QUIC_CIPHER_AES_128_CCM_8_SHA256  /* Kunci 16B, IV 12B, Tag 8B, HKDF SHA-256 */
} QuicCipherSuite;

/* Struktur Konteks Koneksi QUIC */
typedef struct QuicConnection {
    uint8_t dcid[MAX_DCID_LEN];                  /* Destination Connection ID aktif / id koneksi di tabel */
    uint8_t dcid_len;                            /* Panjang byte DCID yang dipakai */

    int sock_server;                             /* Socket UDP server untuk mengirim paket balasan */
    struct sockaddr_in client_addr;              /* Alamat IP dan port UDP klien saat ini */
    socklen_t client_addr_len;                   /* Ukuran struktur client_addr */

    QuicConnectionState state;                   /* Status state machine koneksi QUIC (misal HANDSHAKE / CONNECTED) */
    uint64_t next_packet_number;                 /* Packet number berikutnya untuk paket Initial / 1-RTT keluar */
    uint64_t next_handshake_packet_number;       /* Packet number berikutnya untuk paket Handshake keluar */
    int has_sent_initial;                        /* Flag: 1 jika paket Initial server sudah pernah dikirim */

    SSL *ssl_quic_ctx;                           /* Instance OpenSSL SSL per koneksi untuk TLS 1.3 handshake */

    QuicCipherSuite cipher_suite;                /* Jenis cipher suite TLS 1.3 / QUIC yang dinegosiasikan */
    size_t aead_key_len;                         /* Panjang kunci AEAD/HP dalam byte (16 untuk AES-128, 32 untuk AES-256/ChaCha20) */
    size_t secret_len;                           /* Panjang traffic secret/hash digest dalam byte (32 untuk SHA-256, 48 untuk SHA-384) */

    unsigned char cached_response[4096];         /* Buffer cache respons umum (cadangan / kompatibilitas) */
    size_t cached_response_len;                  /* Panjang data valid di cached_response */
    unsigned char initial_cache[2048];           /* Cache paket Initial server untuk kebutuhan retransmisi[cite: 9] */
    size_t initial_cache_len;                    /* Panjang paket tersimpan di initial_cache[cite: 9] */
    unsigned char handshake_cache[4096];         /* Cache paket Handshake server untuk kebutuhan retransmisi[cite: 9] */
    size_t handshake_cache_len;                  /* Panjang paket tersimpan di handshake_cache[cite: 9] */
    int has_cached_response;                     /* Flag: 1 jika cache Initial/Handshake siap dipakai retransmisi[cite: 9] */

    unsigned char server_handshake_secret[48];   /* Secret handshake sisi server dari keylog TLS 1.3[cite: 9] */
    int has_server_hs_secret;                    /* Flag: 1 jika server_handshake_secret sudah terisi[cite: 9] */
    unsigned char client_handshake_secret[48];   /* Secret handshake sisi klien dari keylog TLS 1.3[cite: 9] */
    int has_client_hs_secret;                    /* Flag: 1 jika client_handshake_secret sudah terisi[cite: 6, 9] */

    int has_client_app_secret;                   /* Flag: 1 jika client_application_traffic_secret_0 sudah terisi[cite: 6, 9] */
    unsigned char client_application_traffic_secret_0[48]; /* Secret 1-RTT sisi klien untuk dekripsi short header[cite: 6, 9] */
    int has_server_app_secret;                   /* Flag: 1 jika server_application_traffic_secret_0 sudah terisi[cite: 6, 9] */
    unsigned char server_application_traffic_secret_0[48]; /* Secret 1-RTT sisi server untuk enkripsi paket 1-RTT[cite: 8, 9] */

    uint64_t handshake_crypto_offset;            /* Offset byte kumulatif frame CRYPTO pada level Handshake[cite: 9] */
    uint64_t tls_hs_seq_num;                     /* Sequence number record TLS 0x17 saat dekripsi handshake[cite: 9] */

    unsigned char server_scid[64];               /* Source Connection ID yang dipakai server pada paket keluar[cite: 1, 9] */
    size_t server_scid_len;                      /* Panjang byte server_scid[cite: 1, 9] */
    unsigned char orig_dcid[20];                 /* Original DCID dari paket Initial pertama klien[cite: 9] */
    size_t orig_dcid_len;                        /* Panjang byte orig_dcid[cite: 9] */

    struct QuicConnection *next;                 /* Pointer berikutnya untuk collision chaining di tabel koneksi */
} QuicConnection;

#define QUIC_HASH_BUCKET_BITS 10 // 2^10 = 1024 buckets
#define QUIC_HASH_BUCKET_SIZE (1 << QUIC_HASH_BUCKET_BITS)

/* Struktur Hash Table Connection QUIC */
typedef struct {
    QuicConnection *buckets[QUIC_HASH_BUCKET_SIZE];
    pthread_mutex_t locks[QUIC_HASH_BUCKET_SIZE];
    size_t total_connections;
} QuicConnTable;

/* API Connection Table */
int core_quic_conn_table_init(QuicConnTable *table);
void core_quic_conn_table_destroy(QuicConnTable *table);

QuicConnection* core_quic_conn_table_find(QuicConnTable *table, const uint8_t *dcid, uint8_t dcid_len);
bool core_quic_conn_table_insert(QuicConnTable *table, QuicConnection *conn);
void core_quic_conn_table_remove(QuicConnTable *table, const uint8_t *dcid, uint8_t dcid_len);
/* Parser Helper untuk Ekstraksi DCID dari Paket UDP Mentah */
int quic_extract_dcid(const uint8_t *packet, size_t packet_len, uint8_t *out_dcid, uint8_t *out_dcid_len);

#endif /* HALMOS_CORE_QUIC_CONN_TABLE_H */