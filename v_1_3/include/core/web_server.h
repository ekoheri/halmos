#ifndef WEB_SERVER_H
#define WEB_SERVER_H


#include "config.h"

/*typedef enum {
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_UNKNOWN
} protocol_type_t;
*/

// Variabel Global (Extern agar bisa diakses main.c jika perlu)
extern Config config;

/**
 * Mengubah program menjadi proses latar belakang (Daemon).
 */

// Prototype Fungsi Utama
void start_server();
void run_server();
void stop_server(int sig);

#endif