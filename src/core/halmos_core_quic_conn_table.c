#include "halmos_core_quic_conn_table.h"
#include <stdlib.h>
#include <string.h>

QuicConnTable quic_conn_table;

/* Algoritma Hash FNV-1a untuk byte array biner DCID */
static uint32_t calculate_dcid_hash(const uint8_t *dcid, uint8_t len) {
    uint32_t hash = 2166136261u;
    for (uint8_t i = 0; i < len; i++) {
        hash ^= dcid[i];
        hash *= 16777619u;
    }
    return hash & (QUIC_HASH_BUCKET_SIZE - 1);
}

int core_quic_conn_table_init(QuicConnTable *table) {
    memset(table->buckets, 0, sizeof(table->buckets));
    for (int i = 0; i < QUIC_HASH_BUCKET_SIZE; i++) {
        if (pthread_mutex_init(&table->locks[i], NULL) != 0) {
            return -1;
        }
    }
    table->total_connections = 0;
    return 0;
}

void core_quic_conn_table_destroy(QuicConnTable *table) {
    for (int i = 0; i < QUIC_HASH_BUCKET_SIZE; i++) {
        pthread_mutex_lock(&table->locks[i]);
        QuicConnection *curr = table->buckets[i];
        while (curr) {
            QuicConnection *next = curr->next;
            if (curr->ssl_quic_ctx) {
                SSL_free(curr->ssl_quic_ctx);
            }
            free(curr);
            curr = next;
        }
        table->buckets[i] = NULL;
        pthread_mutex_unlock(&table->locks[i]);
        pthread_mutex_destroy(&table->locks[i]);
    }
    table->total_connections = 0;
}

QuicConnection* core_quic_conn_table_find(QuicConnTable *table, const uint8_t *dcid, uint8_t dcid_len) {
    uint32_t idx = calculate_dcid_hash(dcid, dcid_len);

    pthread_mutex_lock(&table->locks[idx]);
    QuicConnection *curr = table->buckets[idx];
    while (curr) {
        if (curr->dcid_len == dcid_len && memcmp(curr->dcid, dcid, dcid_len) == 0) {
            pthread_mutex_unlock(&table->locks[idx]);
            return curr;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&table->locks[idx]);
    return NULL;
}

bool core_quic_conn_table_insert(QuicConnTable *table, QuicConnection *conn) {
    uint32_t idx = calculate_dcid_hash(conn->dcid, conn->dcid_len);

    pthread_mutex_lock(&table->locks[idx]);
    
    QuicConnection *curr = table->buckets[idx];
    while (curr) {
        if (curr->dcid_len == conn->dcid_len && memcmp(curr->dcid, conn->dcid, conn->dcid_len) == 0) {
            pthread_mutex_unlock(&table->locks[idx]);
            return false; // Sudah ada
        }
        curr = curr->next;
    }

    conn->next = table->buckets[idx];
    table->buckets[idx] = conn;
    table->total_connections++;

    pthread_mutex_unlock(&table->locks[idx]);
    return true;
}

void core_quic_conn_table_remove(QuicConnTable *table, const uint8_t *dcid, uint8_t dcid_len) {
    uint32_t idx = calculate_dcid_hash(dcid, dcid_len);

    pthread_mutex_lock(&table->locks[idx]);
    QuicConnection *curr = table->buckets[idx];
    QuicConnection *prev = NULL;

    while (curr) {
        if (curr->dcid_len == dcid_len && memcmp(curr->dcid, dcid, dcid_len) == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                table->buckets[idx] = curr->next;
            }
            table->total_connections--;
            pthread_mutex_unlock(&table->locks[idx]);
            
            if (curr->ssl_quic_ctx) {
                SSL_free(curr->ssl_quic_ctx);
            }
            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&table->locks[idx]);
}

/**
 * @brief Mengekstrak Destination Connection ID (DCID) dari paket UDP mentah 
 *        sesuai dengan spesifikasi standar RFC 9000.
 *
 * Fungsi ini melakukan validasi awal terhadap paket masuk:
 * - Memastikan panjang paket minimal mencukupi.
 * - Memvalidasi Fixed Bit (bit ke-6 / 0x40) pada byte pertama wajib bernilai 1.
 * - Membedakan antara Long Header (Initial/Handshake) dan Short Header (1-RTT).
 *
 * @param[in]  packet         Pointer ke buffer data UDP mentah yang diterima.
 * @param[in]  packet_len     Ukuran panjang byte dari paket UDP.
 * @param[out] out_dcid       Buffer penampung hasil ekstraksi DCID.
 * @param[out] out_dcid_len   Pointer untuk menyimpan panjang DCID yang berhasil diekstrak.
 * 
 * @return int 
 *         -  0 jika ekstraksi berhasil dan paket valid.
 *         - -1 jika paket malformasi, gagal validasi Fixed Bit, atau melebihi batas buffer.
 */

int quic_extract_dcid(const uint8_t *packet, size_t packet_len, uint8_t *out_dcid, uint8_t *out_dcid_len) {
    if (packet_len < 1) {
        return -1;
    }

    uint8_t first_byte = packet[0];
    
    // Validasi Sesuai RFC 9000: Fixed Bit (bit ke-6 / 0x40) HARUS bernilai 1.
    if ((first_byte & 0x40) == 0) {
        return -1;
    }

    bool is_long_header = (first_byte & 0x80) != 0;

    if (is_long_header) {
        // --- LONG HEADER ---
        if (packet_len < 6) {
            return -1;
        }

        uint8_t dcid_len = packet[5];
        if (dcid_len == 0 || dcid_len > MAX_DCID_LEN || packet_len < (size_t)(6 + dcid_len)) {
            return -1; 
        }

        memcpy(out_dcid, &packet[6], dcid_len);
        *out_dcid_len = dcid_len;
        return 0;
    } else {
        // --- SHORT HEADER ---
        size_t default_dcid_len = 8; 
        if (packet_len < (1 + default_dcid_len)) {
            return -1;
        }

        memcpy(out_dcid, &packet[1], default_dcid_len);
        *out_dcid_len = (uint8_t)default_dcid_len;
        return 0;
    }
}