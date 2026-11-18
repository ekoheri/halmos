#ifndef HALMOS_SEC_QUIC_CRYPTO_H
#define HALMOS_SEC_QUIC_CRYPTO_H

#include "halmos_core_quic_conn_table.h"

#include <stddef.h>
#include <stdint.h>

int quic_derive_initial_secret(const unsigned char *dcid, size_t dcid_len, unsigned char *out_initial_secret);

int quic_hkdf_expand_label(const unsigned char *secret, const char *label, 
                           const unsigned char *context, size_t context_len, 
                           unsigned char *out, size_t out_len);
                           
int quic_hkdf_expand_label_sha384(const unsigned char *secret, const char *label, 
                                  const unsigned char *context, size_t context_len, 
                                  unsigned char *out, size_t out_len);

int quic_hkdf_expand_label_sha256(const unsigned char *secret, const char *label, 
                                  const unsigned char *hash, size_t hash_len, 
                                  unsigned char *out, size_t out_len); 

int quic_unprotect_header(unsigned char *packet, size_t packet_len, 
                          size_t pn_offset, const unsigned char *hp_key);

int quic_decrypt_payload(const unsigned char *ciphertext, size_t ciphertext_len,
                         const unsigned char *aad, size_t aad_len,
                         const unsigned char *key, const unsigned char *iv,
                         uint64_t packet_number,
                         unsigned char *out_plaintext, size_t *out_plaintext_len); 

size_t quic_build_server_initial_payload(
    uint64_t client_largest_acked,
    const unsigned char *tls_data, size_t tls_data_len,
    unsigned char *out_payload
);

int quic_encrypt_server_initial(
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *dcid, size_t dcid_len,   // DCID dari client (menjadi SCID server)
    const unsigned char *scid, size_t scid_len,   // SCID baru pilihan server (menjadi DCID client)
    uint64_t packet_number,
    const unsigned char *server_key, const unsigned char *server_iv, const unsigned char *server_hp,
    unsigned char *out_packet, size_t *out_packet_len
);

int quic_handle_decryption(const unsigned char *buffer, size_t real_packet_len, size_t pn_offset,
                                    const unsigned char *dcid_ptr, uint8_t dcid_len,
                                    uint8_t *out_decrypted_payload, size_t *out_decrypted_len);

int quic_handle_handshake_decryption(const unsigned char *buffer, size_t real_packet_len, size_t pn_offset,
                                     const unsigned char *client_hs_secret, // Diterima langsung dari hasil keylog/TLS engine
                                     uint8_t *out_decrypted_payload, size_t *out_decrypted_len);

int quic_encrypt_1rtt_packet(int sock_server, struct sockaddr_in *client_addr, socklen_t client_addr_len,
                             QuicConnection *conn, const unsigned char *payload, size_t payload_len);

int quic_handle_1rtt_decryption(const unsigned char *packet, size_t packet_len, 
                                  const unsigned char *app_secret, 
                                  uint8_t dcid_len,
                                  uint8_t *decrypted_out, size_t *decrypted_len);                                     

#endif