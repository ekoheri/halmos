#ifndef HALMOS_TCP_SERVER_H
#define HALMOS_TCP_SERVER_H

// Fungsi untuk membuat server socket utama
int create_server_socket(const char* ip, int port);

// Fungsi utilitas setting socket
void set_nonblocking(int sock);

void setup_socket_security(int sock_client);

#endif
