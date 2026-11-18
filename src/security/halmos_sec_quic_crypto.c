#include "halmos_sec_quic_crypto.h"
#include "halmos_core_quic_conn_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#define QUIC_INITIAL_SALT_LEN 20
// Salt RESMI sesuai spesifikasi RFC 9001 Section 5.2 untuk QUIC v1
static const unsigned char QUIC_INITIAL_SALT[QUIC_INITIAL_SALT_LEN] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

int quic_derive_initial_secret(const unsigned char *dcid, size_t dcid_len, unsigned char *out_initial_secret) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    int ret = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto cleanup;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY; // WAJIB EXTRACT ONLY sesuai RFC 9001
    OSSL_PARAM params[5];
    size_t idx = 0;

    params[idx++] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[idx++] = OSSL_PARAM_construct_int("mode", &mode);
    params[idx++] = OSSL_PARAM_construct_octet_string("salt", (void *)QUIC_INITIAL_SALT, QUIC_INITIAL_SALT_LEN);
    params[idx++] = OSSL_PARAM_construct_octet_string("key", (void *)dcid, dcid_len);
    params[idx] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out_initial_secret, 32, params) <= 0) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (kdf) EVP_KDF_free(kdf);
    return ret;
}

int quic_hkdf_expand_label(const unsigned char *secret, const char *label, 
                           const unsigned char *context, size_t context_len, 
                           unsigned char *out, size_t out_len) {
    unsigned char info[256];
    size_t label_len = strlen(label);
    size_t info_len = 0;

    info[0] = (out_len >> 8) & 0xFF;
    info[1] = out_len & 0xFF;
    info_len += 2;

    info[2] = (uint8_t)(label_len + 6);
    info_len += 1;

    memcpy(info + info_len, "tls13 ", 6);
    info_len += 6;
    memcpy(info + info_len, label, label_len);
    info_len += label_len;

    info[info_len] = (uint8_t)context_len;
    info_len += 1;
    if (context_len > 0) {
        memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    int ret = 0;

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY; // WAJIB EXPAND ONLY untuk tahap label expansion
    OSSL_PARAM params[5];
    size_t idx = 0;
    
    params[idx++] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[idx++] = OSSL_PARAM_construct_int("mode", &mode);
    params[idx++] = OSSL_PARAM_construct_octet_string("key", (void *)secret, 32); 
    params[idx++] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
    params[idx] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) > 0) {
        ret = 1;
    }

    if (kctx) EVP_KDF_CTX_free(kctx);
    if (kdf) EVP_KDF_free(kdf);
    return ret;
}

int quic_hkdf_expand_label_sha384(const unsigned char *secret, const char *label, 
                                  const unsigned char *context, size_t context_len, 
                                  unsigned char *out, size_t out_len) {
    unsigned char info[256];
    size_t label_len = strlen(label);
    size_t info_len = 0;

    info[0] = (out_len >> 8) & 0xFF;
    info[1] = out_len & 0xFF;
    info_len += 2;

    info[2] = (uint8_t)(label_len + 6);
    info_len += 1;

    memcpy(info + info_len, "tls13 ", 6);
    info_len += 6;
    memcpy(info + info_len, label, label_len);
    info_len += label_len;

    info[info_len] = (uint8_t)context_len;
    info_len += 1;
    if (context_len > 0) {
        memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    int ret = 0;

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[5];
    size_t idx = 0;
    
    params[idx++] = OSSL_PARAM_construct_utf8_string("digest", "SHA384", 0);
    params[idx++] = OSSL_PARAM_construct_int("mode", &mode);
    params[idx++] = OSSL_PARAM_construct_octet_string("key", (void *)secret, 48); 
    params[idx++] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
    params[idx] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) > 0) {
        ret = 1;
    }

    if (kctx) EVP_KDF_CTX_free(kctx);
    if (kdf) EVP_KDF_free(kdf);
    return ret;
}

int quic_hkdf_expand_label_sha256(const unsigned char *secret, const char *label, 
                                  const unsigned char *hash, size_t hash_len, 
                                  unsigned char *out, size_t out_len) {
    // Format TLS 1.3 HkdfLabel:
    // struct {
    //     uint16 length = out_len;
    //     opaque label<7..255> = "tls13 " + label;
    //     opaque context<0..255> = hash;
    // } HkdfLabel;
    
    unsigned char hkdf_label[512];
    size_t label_len = strlen(label);
    size_t full_label_len = 6 + label_len; // "tls13 " adalah 6 byte + panjang label
    size_t total_len = 2 + 1 + full_label_len + 1 + hash_len;

    size_t pos = 0;
    // Length (2 bytes, network byte order)
    hkdf_label[pos++] = (unsigned char)(out_len >> 8);
    hkdf_label[pos++] = (unsigned char)(out_len & 0xFF);

    // Label length (1 byte)
    hkdf_label[pos++] = (unsigned char)full_label_len;

    // Label content: "tls13 " + label
    memcpy(hkdf_label + pos, "tls13 ", 6);
    pos += 6;
    memcpy(hkdf_label + pos, label, label_len);
    pos += label_len;

    // Context length (1 byte) + Context
    hkdf_label[pos++] = (unsigned char)hash_len;
    if (hash && hash_len > 0) {
        memcpy(hkdf_label + pos, hash, hash_len);
        pos += hash_len;
    }

    // Eksekusi HKDF-Expand dengan EVP_PKEY / HKDF OpenSSL
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    int ret = 0;
    if (EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, 32) > 0 && // Secret TLS 1.3 berukuran 32 byte (SHA-256) atau 48 byte
        EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label, pos) > 0) {
        
        if (EVP_PKEY_derive(pctx, out, &out_len) > 0) {
            ret = 1;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int quic_unprotect_header(unsigned char *packet, size_t packet_len, 
                          size_t pn_offset, const unsigned char *hp_key) {
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen = 0;
    unsigned char sample[16];
    unsigned char mask[16]; // PERBAIKAN KRITIS: Diperbesar jadi 16 byte penuh untuk mencegah stack corruption dari AES-ECB
    uint8_t first_byte_mask = 0;
    int ret = 0;

    size_t sample_offset = pn_offset + 4;
    if (sample_offset + 16 > packet_len) {
        fprintf(stderr, "[HP DEBUG ERROR] Buffer tidak cukup untuk sampel! sample_offset=%zu, packet_len=%zu\n", sample_offset, packet_len);
        return 0;
    }

    memcpy(sample, packet + sample_offset, 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp_key, NULL)) {
        goto cleanup;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_EncryptUpdate(ctx, mask, &outlen, sample, 16)) {
        goto cleanup;
    }

    if ((packet[0] & 0x80) == 0x80) {
        first_byte_mask = (mask[0] & 0x0f);
        packet[0] ^= first_byte_mask;
    } else {
        first_byte_mask = (mask[0] & 0x1f);
        packet[0] ^= first_byte_mask;
    }

    size_t pn_length = (packet[0] & 0x03) + 1;

    for (size_t i = 0; i < pn_length; i++) {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    ret = 1;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int quic_decrypt_payload(const unsigned char *ciphertext_with_tag, size_t ciphertext_with_tag_len,
                         const unsigned char *aad, size_t aad_len,
                         const unsigned char *key, const unsigned char *iv,
                         uint64_t packet_number,
                         unsigned char *out_plaintext, size_t *out_plaintext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret = 0;
    unsigned char nonce[12];

    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= (unsigned char)(packet_number >> (8 * i));
    }

    if (ciphertext_with_tag_len < 16) {
        return 0;
    }

    size_t actual_ct_len = ciphertext_with_tag_len - 16;
    const unsigned char *tag = ciphertext_with_tag + actual_ct_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto cleanup;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto cleanup;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto cleanup;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag)) {
        goto cleanup;
    }

    if (aad_len > 0) {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len)) {
            goto cleanup;
        }
    }

    if (!EVP_DecryptUpdate(ctx, out_plaintext, &len, ciphertext_with_tag, (int)actual_ct_len)) {
        goto cleanup;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, out_plaintext + plaintext_len, &len) <= 0) {
        goto cleanup;
    }
    plaintext_len += len;
    *out_plaintext_len = (size_t)plaintext_len;

    ret = 1;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

size_t quic_build_server_initial_payload(
    uint64_t client_largest_acked,
    const unsigned char *tls_data, size_t tls_data_len,
    unsigned char *out_payload
) {
    (void)client_largest_acked;
    size_t pos = 0;

    out_payload[pos++] = 0x06; 
    out_payload[pos++] = 0x00; 

    if (tls_data_len < 64) {
        out_payload[pos++] = (unsigned char)tls_data_len;
    } else if (tls_data_len < 16384) {
        out_payload[pos++] = (unsigned char)(0x40 | (tls_data_len >> 8));
        out_payload[pos++] = (unsigned char)(tls_data_len & 0xFF);
    } else {
        out_payload[pos++] = (unsigned char)(0x80 | (tls_data_len >> 24));
        out_payload[pos++] = (unsigned char)((tls_data_len >> 16) & 0xFF);
        out_payload[pos++] = (unsigned char)((tls_data_len >> 8) & 0xFF);
        out_payload[pos++] = (unsigned char)(tls_data_len & 0xFF);
    }

    memcpy(out_payload + pos, tls_data, tls_data_len);
    pos += tls_data_len;

    return pos;
}

int quic_encrypt_server_initial(
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *dcid, size_t dcid_len,   
    const unsigned char *scid, size_t scid_len,   
    uint64_t packet_number,
    const unsigned char *server_key, const unsigned char *server_iv, const unsigned char *server_hp,
    unsigned char *out_packet, size_t *out_packet_len
) {
    unsigned char work_buf[65535];
    size_t pos = 0;

    work_buf[pos++] = 0xC0 | 0x00;
    work_buf[pos++] = 0x00;
    work_buf[pos++] = 0x00;
    work_buf[pos++] = 0x00;
    work_buf[pos++] = 0x01;

    work_buf[pos++] = (unsigned char)scid_len;
    memcpy(work_buf + pos, scid, scid_len);
    pos += scid_len;

    work_buf[pos++] = (unsigned char)dcid_len;
    memcpy(work_buf + pos, dcid, dcid_len);
    pos += dcid_len;

    work_buf[pos++] = 0x00;

    size_t est_header_len = pos;
    size_t tag_len = 16;
    size_t target_total_len = 1200;
    
    size_t final_plaintext_len = plaintext_len;
    unsigned char padded_plaintext[65535];
    const unsigned char *final_plaintext = plaintext;

    size_t current_est = est_header_len + 2 + 1 + plaintext_len + tag_len;
    if (current_est < target_total_len) {
        size_t padding_needed = target_total_len - current_est;
        memcpy(padded_plaintext, plaintext, plaintext_len);
        memset(padded_plaintext + plaintext_len, 0x00, padding_needed);
        final_plaintext = padded_plaintext;
        final_plaintext_len = plaintext_len + padding_needed;
    }

    size_t remaining_len = 1 + final_plaintext_len + tag_len;

    work_buf[pos++] = (unsigned char)(0x40 | (remaining_len >> 8));
    work_buf[pos++] = (unsigned char)(remaining_len & 0xFF);

    size_t pn_offset = pos;
    work_buf[pos++] = (unsigned char)(packet_number & 0xFF);

    size_t aad_len = pos;
    const unsigned char *aad = work_buf;

    unsigned char nonce[12];
    memcpy(nonce, server_iv, 12);
    for (size_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= (unsigned char)(packet_number >> (8 * i));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, ciphertext_len = 0;
    unsigned char *ciphertext_dest = work_buf + pos;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) ||
        !EVP_EncryptInit_ex(ctx, NULL, NULL, server_key, nonce) ||
        !EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) ||
        !EVP_EncryptUpdate(ctx, ciphertext_dest, &len, final_plaintext, (int)final_plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;
    pos += ciphertext_len;

    unsigned char tag[16];
    if (!EVP_EncryptFinal_ex(ctx, ciphertext_dest + ciphertext_len, &len) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    memcpy(ciphertext_dest + ciphertext_len, tag, 16);
    pos += 16;
    EVP_CIPHER_CTX_free(ctx);

    size_t sample_offset = pn_offset + 4;
    unsigned char sample[16];
    memcpy(sample, work_buf + sample_offset, 16);

    unsigned char mask[16]; // PERBAIKAN KRITIS: Diperbesar menjadi 16 byte penuh
    int outlen = 0;
    EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
    if (!hp_ctx) return 0;

    if (!EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, server_hp, NULL)) {
        EVP_CIPHER_CTX_free(hp_ctx);
        return 0;
    }
    EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
    EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
    EVP_CIPHER_CTX_free(hp_ctx);

    work_buf[0] ^= (mask[0] & 0x0f);
    work_buf[pn_offset] ^= mask[1];

    memcpy(out_packet, work_buf, pos);
    *out_packet_len = pos;

    return 1;
}

int quic_handle_decryption(const unsigned char *buffer, size_t real_packet_len, size_t pn_offset,
                                    const unsigned char *dcid_ptr, uint8_t dcid_len,
                                    uint8_t *out_decrypted_payload, size_t *out_decrypted_len) {
    unsigned char initial_secret[32];
    unsigned char client_initial_secret[32];
    unsigned char client_key[16];
    unsigned char client_iv[12];
    unsigned char client_hp[16];

    if (!quic_derive_initial_secret(dcid_ptr, dcid_len, initial_secret) ||
        !quic_hkdf_expand_label(initial_secret, "client in", NULL, 0, client_initial_secret, 32)) {
        return 0;
    }

    quic_hkdf_expand_label(client_initial_secret, "quic key", NULL, 0, client_key, 16);
    quic_hkdf_expand_label(client_initial_secret, "quic iv", NULL, 0, client_iv, 12);
    quic_hkdf_expand_label(client_initial_secret, "quic hp", NULL, 0, client_hp, 16);

    unsigned char work_buffer[65535];
    if (real_packet_len > sizeof(work_buffer)) return 0;
    memcpy(work_buffer, buffer, real_packet_len);

    if (!quic_unprotect_header(work_buffer, real_packet_len, pn_offset, client_hp)) {
        return 0;
    }

    size_t pn_len = (work_buffer[0] & 0x03) + 1;
    uint64_t packet_number = 0;
    for (size_t j = 0; j < pn_len; j++) {
        packet_number = (packet_number << 8) | work_buffer[pn_offset + j];
    }

    size_t aad_len = pn_offset + pn_len;
    const unsigned char *aad = work_buffer;
    const unsigned char *ciphertext = work_buffer + aad_len;
    size_t ciphertext_len = real_packet_len - aad_len;

    return quic_decrypt_payload(ciphertext, ciphertext_len, aad, aad_len,
                                client_key, client_iv, packet_number,
                                out_decrypted_payload, out_decrypted_len);
}

int quic_handle_handshake_decryption(const unsigned char *buffer, size_t real_packet_len, size_t pn_offset,
                                     const unsigned char *client_hs_secret, // Diterima langsung dari hasil keylog/TLS engine
                                     uint8_t *out_decrypted_payload, size_t *out_decrypted_len) {
    unsigned char client_hs_key[16];
    unsigned char client_hs_iv[12];
    unsigned char client_hs_hp[16];

    // Turunkan key, IV, dan HP khusus untuk QUIC Handshake menggunakan secret yang sah (SHA-384)
    quic_hkdf_expand_label_sha384(client_hs_secret, "quic key", NULL, 0, client_hs_key, 16);
    quic_hkdf_expand_label_sha384(client_hs_secret, "quic iv", NULL, 0, client_hs_iv, 12);
    quic_hkdf_expand_label_sha384(client_hs_secret, "quic hp", NULL, 0, client_hs_hp, 16);

    unsigned char work_buffer[65535];
    if (real_packet_len > sizeof(work_buffer)) return 0;
    memcpy(work_buffer, buffer, real_packet_len);

    if (!quic_unprotect_header(work_buffer, real_packet_len, pn_offset, client_hs_hp)) {
        return 0;
    }

    size_t pn_len = (work_buffer[0] & 0x03) + 1;
    uint64_t packet_number = 0;
    for (size_t j = 0; j < pn_len; j++) {
        packet_number = (packet_number << 8) | work_buffer[pn_offset + j];
    }

    size_t aad_len = pn_offset + pn_len;
    const unsigned char *aad = work_buffer;
    const unsigned char *ciphertext = work_buffer + aad_len;
    size_t ciphertext_len = real_packet_len - aad_len;

    return quic_decrypt_payload(ciphertext, ciphertext_len, aad, aad_len,
                                client_hs_key, client_hs_iv, packet_number,
                                out_decrypted_payload, out_decrypted_len);
}

int quic_encrypt_1rtt_packet(int sock_server, struct sockaddr_in *client_addr, socklen_t client_addr_len,
                             QuicConnection *conn, const unsigned char *payload, size_t payload_len) {
    if (!conn->has_server_app_secret) {
        fprintf(stderr, "[QUIC 1-RTT OUT ERROR] Server Application Traffic Secret belum tersedia!\n");
        return 0;
    }

    // 1. Turunkan Kunci 1-RTT dari server_application_traffic_secret_0
    unsigned char key[16], iv[12], hp[16];
    // Menggunakan HMAC-SHA256 untuk TLS 1.3 key derivation di QUIC
    quic_hkdf_expand_label_sha256(conn->server_application_traffic_secret_0, "quic key", NULL, 0, key, 16);
    quic_hkdf_expand_label_sha256(conn->server_application_traffic_secret_0, "quic iv", NULL, 0, iv, 12);
    quic_hkdf_expand_label_sha256(conn->server_application_traffic_secret_0, "quic hp", NULL, 0, hp, 16);

    unsigned char packet_out[4096];
    size_t pkt_pos = 0;

    // 2. Susun Short Header (1-RTT Packet)
    // Format: 0 1 r r r r r p (Bit 7 = 0, Bit 6 = 1 [Fixed Bit], Spin bit, Key Phase, Packet Number Length - 1)
    // Menggunakan Packet Number Length 1 byte (PN Len = 0 -> mask & 0x03 = 0)
    unsigned char first_byte = 0x40; // 01000000 (Short header, Fixed bit = 1)
    packet_out[pkt_pos++] = first_byte;

    // Destination Connection ID (DCID) milik klien
    memcpy(packet_out + pkt_pos, conn->dcid, conn->dcid_len);
    pkt_pos += conn->dcid_len;

    size_t pn_offset = pkt_pos;
    // Placeholder untuk Packet Number (1 byte)
    packet_out[pkt_pos++] = (unsigned char)(conn->next_packet_number & 0xFF);

    size_t aad_len = pkt_pos;
    const unsigned char *aad = packet_out;

    // 3. Bungkus payload ke dalam QUIC STREAM Frame (Type 0x08 = Stream Frame dengan len & off)
    unsigned char quic_frame[4096];
    size_t qf_pos = 0;
    quic_frame[qf_pos++] = 0x08; // Stream Frame Type (STREAM ID 0, dsb.)
    quic_frame[qf_pos++] = 0x00; // Stream ID 0 (Varint 1 byte)
    quic_frame[qf_pos++] = 0x00; // Offset 0 (Varint 1 byte)
    
    // Varint encoding untuk length payload
    if (payload_len < 64) {
        quic_frame[qf_pos++] = (unsigned char)payload_len;
    } else {
        quic_frame[qf_pos++] = (unsigned char)(0x40 | (payload_len >> 8));
        quic_frame[qf_pos++] = (unsigned char)(payload_len & 0xFF);
    }
    memcpy(quic_frame + qf_pos, payload, payload_len);
    qf_pos += payload_len;

    // 4. Hitung Nonce (IV XOR Packet Number)
    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (size_t k = 0; k < 8; k++) {
        nonce[11 - k] ^= (unsigned char)(conn->next_packet_number >> (8 * k));
    }

    // 5. Enkripsi Payload dengan AES-128-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ct_len = 0;
    unsigned char *ct_dest = packet_out + pkt_pos;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) &&
        EVP_EncryptUpdate(ctx, ct_dest, &len, quic_frame, (int)qf_pos)) {
        
        ct_len = len;
        pkt_pos += ct_len;

        unsigned char tag[16];
        if (EVP_EncryptFinal_ex(ctx, ct_dest + ct_len, &len) &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            
            memcpy(ct_dest + ct_len, tag, 16);
            pkt_pos += 16;

            // 6. Header Protection Masking (AES-ECB dengan kunci HP)
            size_t sample_off = pn_offset + 4; // Sampel ciphertext setelah packet number
            unsigned char sample[16];
            memcpy(sample, packet_out + sample_off, 16);

            unsigned char mask[16];
            int outlen = 0;
            EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
            if (hp_ctx) {
                EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, hp, NULL);
                EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
                EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
                
                // Terapkan mask ke byte pertama (mengambil 4 bit terbawah) dan packet number
                packet_out[0] ^= (mask[0] & 0x0f);
                packet_out[pn_offset] ^= mask[1];
                EVP_CIPHER_CTX_free(hp_ctx);
            }

            // 7. Kirim paket 1-RTT ke klien via UDP
            sendto(sock_server, packet_out, pkt_pos, 0, (struct sockaddr *)client_addr, client_addr_len);
            conn->next_packet_number++;
            fprintf(stderr, "[QUIC 1-RTT OUT] Sukses mengirim paket 1-RTT (%zu bytes)\n", pkt_pos);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int quic_handle_1rtt_decryption(const unsigned char *packet, size_t packet_len, 
                                  const unsigned char *app_secret, 
                                  uint8_t dcid_len,
                                  uint8_t *decrypted_out, size_t *decrypted_len) {
    // 1. Header Protection Unmasking pada Short Header
    // Byte pertama dilindungi bit 0-4, Packet Number dimulai setelah DCID + Packet Number (1-4 bytes)
    size_t pn_offset = 1 + dcid_len; // Estimasi awal posisi packet number
    if (packet_len < pn_offset + 4 + 16) return 0;

    unsigned char hp_key[16], key[16], iv[12];
    quic_hkdf_expand_label_sha384(app_secret, "quic hp", NULL, 0, hp_key, 16);
    quic_hkdf_expand_label_sha384(app_secret, "quic key", NULL, 0, key, 16);
    quic_hkdf_expand_label_sha384(app_secret, "quic iv", NULL, 0, iv, 12);

    // Ambil sample untuk HP mask
    unsigned char sample[16];
    memcpy(sample, packet + pn_offset + 4, 16);

    unsigned char mask[16];
    int outlen = 0;
    EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), NULL, hp_key, NULL);
    EVP_CIPHER_CTX_set_padding(hp_ctx, 0);
    EVP_EncryptUpdate(hp_ctx, mask, &outlen, sample, 16);
    EVP_CIPHER_CTX_free(hp_ctx);

    // Unmask byte pertama dan packet number
    unsigned char unprotected_first_byte = packet[0] ^ (mask[0] & 0x1f);
    int pn_length = (unprotected_first_byte & 0x03) + 1;

    unsigned char unprotected_pn[4];
    for (int i = 0; i < pn_length; i++) {
        unprotected_pn[i] = packet[pn_offset + i] ^ mask[1 + i];
    }

    size_t ciphertext_offset = pn_offset + pn_length;
    size_t ciphertext_len = packet_len - ciphertext_offset;

    // 2. AES-GCM Decryption Payload
    // Nonce = IV XOR Packet Number
    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    uint64_t pkt_num = 0;
    for (int i = 0; i < pn_length; i++) {
        pkt_num = (pkt_num << 8) | unprotected_pn[i];
    }
    for (size_t k = 0; k < 8; k++) {
        nonce[11 - k] ^= (unsigned char)(pkt_num >> (8 * k));
    }

    // AAD adalah header paket yang tidak dienkripsi (dari byte 0 sampai ciphertext_offset)
    const unsigned char *aad = packet;
    size_t aad_len = ciphertext_offset;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plain_len = 0;
    int success = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) &&
        EVP_DecryptUpdate(ctx, decrypted_out, &len, packet + ciphertext_offset, (int)ciphertext_len)) {
        
        plain_len = len;
        if (EVP_DecryptFinal_ex(ctx, decrypted_out + plain_len, &len) > 0) {
            *decrypted_len = plain_len + len;
            success = 1;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return success;
}