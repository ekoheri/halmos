#include "halmos_tcp_server.h"
#include "halmos_global.h"
#include "halmos_config.h"
#include "halmos_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

// Tambahkan TCP Fast Open
int qlen = 5;
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

Config config;

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