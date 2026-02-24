#ifndef HALMOS_CORE_TCP_SERVER_H
#define HALMOS_CORE_TCP_SERVER_H

// Fungsi untuk membuat server socket utama
int tcp_create_server(const char* ip, int port);

// Fungsi utilitas setting socket
void tcp_set_nonblocking(int sock);

#endif
