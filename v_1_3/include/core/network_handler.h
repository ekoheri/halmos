#ifndef NETWORK_HANDLER_H
#define NETWORK_HANDLER_H

// Pindahan dari web_server.h agar tidak circular
typedef enum {
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_UNKNOWN
} protocol_type_t;

// Fungsi untuk membuat server socket utama
int create_server_socket(const char* ip, int port);

// Fungsi utilitas setting socket
void set_nonblocking(int sock);

// Fungsi mengintip isi paket awal
protocol_type_t detect_protocol(int client_fd);

#endif