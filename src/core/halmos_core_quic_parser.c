#include "halmos_core_quic_parser.h"
#include "halmos_core_quic_conn_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int core_quic_parser_extract_dcid(const uint8_t *packet, size_t packet_len, uint8_t *out_dcid, uint8_t *out_dcid_len) {
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

int core_quic_parser_parse_packet_header(const unsigned char *buffer, size_t nbytes, 
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

const unsigned char *core_quic_parser_extract_tls_from_crypto_frame(
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