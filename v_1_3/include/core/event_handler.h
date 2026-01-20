#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

// #include "network_handler.h" // Butuh protocol_type_t untuk handle_client

// Setup limit FD dan jumlah event epoll
void setup_event_system();

// Fungsi yang dijalankan oleh thread di thread pool
void* worker_routine(void* arg);

// Fungsi logika penentuan handler protokol
int handle_client(int sock_client);

#endif