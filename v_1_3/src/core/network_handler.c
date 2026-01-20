#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#include "network_handler.h"
#include "log.h"

// Tambahkan TCP Fast Open
int qlen = 5;
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

/********************************************************************
 * set_nonblocking()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti mengubah cara pelayan bekerja.
 *
 * Normal blocking:
 *   Pelayan menunggu satu pelanggan selesai bicara dulu
 *   baru bisa melayani yang lain.
 *
 * Non-blocking:
 *   Pelayan bisa bilang:
 *   “Silakan pikir dulu pesanannya, saya layani meja lain.”
 *
 * Sehingga satu thread tidak tersandera oleh satu klien.
 ********************************************************************/
void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        write_log("Error : fcntl F_GETFL");
        return;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        write_log("Error : fcntl F_SETFL");
    }
}
/********************************************************************
 * detect_protocol()
 * ---------------------------------------------------------------
 * Analogi:
 * Ini seperti resepsionis yang hanya “mengintip” gaya bicara tamu
 * tanpa langsung mengajaknya ngobrol.
 *
 * - Kalau tamu membuka dengan kalimat resmi ala HTTP/2,
 *   berarti tamu VIP (HTTP2).
 * - Kalau mulai dengan “GET /”, “POST /” → tamu biasa HTTP/1.
 *
 * MSG_PEEK = mengintip tanpa menghapus data asli,
 * seperti melihat dari balik kaca tanpa memanggil tamu masuk.
 ********************************************************************/

protocol_type_t detect_protocol(int client_fd) {
    char buffer[24];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer), MSG_PEEK);
    if (n <= 0) return PROTO_UNKNOWN;

    // Cek Magic String HTTP/2: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if (n >= 24 && memcmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        return PROTO_HTTP2;
    }

    // Jika diawali string metode HTTP umum, maka itu HTTP/1
    if (n >= 3 && (memcmp(buffer, "GET", 3) == 0 || 
                   memcmp(buffer, "POS", 3) == 0 || 
                   memcmp(buffer, "HEA", 3) == 0 ||
                   memcmp(buffer, "PUT", 3) == 0 ||
                   memcmp(buffer, "DEL", 3) == 0)) {
        return PROTO_HTTP1;
    }

    // Default jika tidak yakin, biarkan HTTP/1 manager yang mencoba memprosesnya
    return PROTO_HTTP1;
}

int create_server_socket(const char* ip, int port) {
    int sock_server;
    int opt = 1;
    int qlen = 5;
    struct sockaddr_in serv_addr;

    sock_server = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_server < 0) {
        perror("Socket creation failed");
        return -1;
    }

    setsockopt(sock_server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(sock_server);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if (bind(sock_server, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        write_log("Proses bind gagal pada %s:%d", ip, port);
        return -1;
    }

    if (listen(sock_server, 4096) < 0) {
        perror("Listen failed");
        return -1;
    }

    setsockopt(sock_server, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
    int send_buf = 1024 * 1024; 
    setsockopt(sock_server, SOL_SOCKET, SO_SNDBUF, &send_buf, sizeof(send_buf));

    return sock_server;
}