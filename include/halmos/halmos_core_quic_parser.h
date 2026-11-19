#ifndef HALMOS_CORE_QUIC_PARSER_H
#define HALMOS_CORE_QUIC_PARSER_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Mengekstrak Destination Connection ID (DCID) dari paket UDP mentah.
 */
int core_quic_parser_extract_dcid(const uint8_t *packet, size_t packet_len, uint8_t *out_dcid, uint8_t *out_dcid_len);

/**
 * @brief Memparsing header paket QUIC (Initial/Handshake) untuk mendapatkan offset packet number dan ukuran paket.
 */
int core_quic_parser_parse_packet_header(const unsigned char *buffer, size_t nbytes, 
                                         size_t *out_pn_offset, size_t *out_real_packet_len, 
                                         const unsigned char **out_dcid_ptr, uint8_t *out_dcid_len,
                                         const unsigned char **out_scid_ptr, uint8_t *out_scid_len,
                                         int *out_pkt_type);

/**
 * @brief Mengekstrak payload TLS murni dari dalam QUIC CRYPTO Frame.
 */
const unsigned char *core_quic_parser_extract_tls_from_crypto_frame(
    const unsigned char *payload, size_t payload_len, size_t *out_tls_len
);

#endif /* HALMOS_CORE_QUIC_PARSER_H */