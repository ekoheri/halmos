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

/* Struktur Konteks Koneksi QUIC */
typedef struct QuicConnection {
    uint8_t dcid[MAX_DCID_LEN];
    uint8_t dcid_len;

    int sock_server; 
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    QuicConnectionState state;
    uint64_t next_packet_number;
    uint64_t next_handshake_packet_number;
    int has_sent_initial;
    
    SSL *ssl_quic_ctx; 

    unsigned char cached_response[4096];
    size_t cached_response_len;
    unsigned char initial_cache[2048];
    size_t initial_cache_len;
    unsigned char handshake_cache[4096];
    size_t handshake_cache_len;
    int has_cached_response;
    unsigned char server_handshake_secret[48];
    int has_server_hs_secret;
    unsigned char client_handshake_secret[48];
    int has_client_hs_secret;
    int has_client_app_secret;
    unsigned char client_application_traffic_secret_0[48];    
    int has_server_app_secret;
    unsigned char server_application_traffic_secret_0[48];

    struct QuicConnection *next; /* Collision Resolution (Chaining) */
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