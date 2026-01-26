#ifndef HALMOS_HTTP_BRIDGE_H
#define HALMOS_HTTP_BRIDGE_H

#include <sys/types.h>

/**
 * Tipe Protokol yang didukung Halmos
 */
typedef enum {
    PROTOCOL_HTTP1,
    PROTOCOL_HTTP2,
    PROTOCOL_UNKNOWN,
    PROTOCOL_ERROR,
    PROTOCOL_RETRY
} halmos_protocol_t;

/**
 * halmos_bridge_detect
 * -------------------
 * Mengintip buffer socket untuk menentukan protokol tanpa mengambil data (Zero-Loss).
 * * @param client_fd : File descriptor milik client
 * @return halmos_protocol_t : Hasil deteksi (HTTP1 atau HTTP2)
 */
halmos_protocol_t bridge_detect(int socket_client);

/**
 * halmos_bridge_dispatch
 * ----------------------
 * Menentukan arah aliran data. Fungsi ini yang akan memanggil handler 
 * masing-masing protokol setelah deteksi berhasil.
 */
int bridge_dispatch(int sock_client);

#endif