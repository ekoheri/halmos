#ifndef HALMOS_TRANSPORT_UDP_SERVER_H
#define HALMOS_TRANSPORT_UDP_SERVER_H

/**
 * Mengatur socket UDP menjadi non-blocking mode.
 */
void udp_set_nonblocking(int sock);

/**
 * Membuat dan menginisialisasi server socket UDP (SOCK_DGRAM) untuk QUIC/HTTP/3.
 * Mengembalikan file descriptor socket jika berhasil, atau -1 jika gagal.
 */
int udp_create_server(const char* ip, int port);


#endif /* HALMOS_TRANSPORT_UDP_SERVER_H */