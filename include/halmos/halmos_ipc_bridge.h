#ifndef HALMOS_IPC_BRIDGE_H
#define HALMOS_IPC_BRIDGE_H

#include <stdbool.h>

/**
 * Inisialisasi socket UDS. 
 * Dipanggil sekali di start_event_loop().
 */
int setup_uds_bridge(const char *path);

/**
 * Handler utama saat bridge_fd terdeteksi EPOLLIN di main loop.
 * Ini yang akan melakukan routing internal.
 */
void handle_bridge_request(int bridge_fd);

#endif