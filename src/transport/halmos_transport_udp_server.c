/*
CATATAN UNTUK QPACK AMBI DARI SINI

https://github.com/ngtcp2/nghttp3/tree/main/lib
*/

#include "halmos_transport_udp_server.h"
#include "halmos_global.h"
#include "halmos_core_config.h"
#include "halmos_log.h"
#include "halmos_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

void udp_set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        write_log_error_code(ERR_TR_SOCKET_FLAGS, sock);
        return;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        write_log_error_code(ERR_TR_NONBLOCK, sock);
    }
}

int udp_create_server(const char* ip, int port) {
    int sock_server;
    int opt = 1;
    struct sockaddr_in serv_addr;

    /* UDP menggunakan SOCK_DGRAM untuk QUIC */
    sock_server = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_server < 0) {
        write_log_error_code(ERR_TR_CREATE_MASTER, strerror(errno));
        return -1;
    }

    /* Mengizinkan reuse address dan port untuk load balancing antar worker thread */
    if (setsockopt(sock_server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        write_log_error_code(ERR_TR_SOCKET_FLAGS, sock_server);
    }

    udp_set_nonblocking(sock_server);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if (bind(sock_server, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        write_log_error_code(ERR_TR_BIND, ip, port);
        close(sock_server);
        return -1;
    }

    /* Catatan: Tidak ada fungsi listen() atau accept() untuk UDP.
     * Epoll di Halmos nantinya akan memantau sock_server ini menggunakan EPOLLIN
     * untuk membaca datagram masuk menggunakan recvmsg().
     */

    /* Mengoptimalkan ukuran buffer socket UDP (mencegah packet drop pada traffic tinggi) */
    int rcv_buf = 2 * 1024 * 1024; /* 2 MB */
    int snd_buf = 2 * 1024 * 1024; /* 2 MB */
    setsockopt(sock_server, SOL_SOCKET, SO_RCVBUF, &rcv_buf, sizeof(rcv_buf));
    setsockopt(sock_server, SOL_SOCKET, SO_SNDBUF, &snd_buf, sizeof(snd_buf));

    return sock_server;
}