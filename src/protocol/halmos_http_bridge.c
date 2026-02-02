#include "halmos_http_bridge.h"
#include "halmos_http1_manager.h"

#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/**
 * Logika "Mengintip" Protokol
 */
halmos_protocol_t bridge_detect(int sock_client) {
    char buffer[24];
    
    // Gunakan MSG_PEEK + MSG_DONTWAIT agar tidak nge-hang
    ssize_t n = recv(sock_client, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Data belum sampai di kernel, suruh worker nunggu dikit atau return khusus
            return PROTOCOL_RETRY; // Buat enum baru atau handle ini
        }
        return PROTOCOL_ERROR;
    }

    if (n == 0) return PROTOCOL_ERROR; // Koneksi ditutup lawan

    // Sementara kita hajar dulu sebagai HTTP1
    return PROTOCOL_HTTP1;
}

/**
 * Logika Pengalihan Aliran (Multiplexer)
 */
int bridge_dispatch(int sock_client) {
    halmos_protocol_t proto = bridge_detect(sock_client);
    int result = 0;

    switch (proto) {
        case PROTOCOL_HTTP1:
            result = handle_http1_session(sock_client);
            break;

        // Kita tumpuk semua sisa kemungkinan di sini 
        // supaya compiler tahu kita sudah "sadar" akan opsi ini.
        case PROTOCOL_HTTP2:
        case PROTOCOL_UNKNOWN:
        case PROTOCOL_ERROR:
        default:
            result = 0; 
            break;
    }
    return result;
}
