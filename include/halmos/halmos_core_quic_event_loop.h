#ifndef CORE_QUIC_EVENT_LOOP_H
#define CORE_QUIC_EVENT_LOOP_H

#include <stdbool.h>

/**
 * Menginisialisasi epoll instance, alokasi adaptive event batch, 
 * socket server UDP, dan meluncurkan background thread untuk QUIC poller.
 * Mengembalikan true jika sukses, atau false jika gagal.
 */
bool core_quic_event_loop_start(void);

/**
 * Menghentikan poller QUIC secara graceful (mengubah flag atomic running,
 * menunggu thread join, dan membersihkan seluruh resource epoll serta socket).
 */
void core_quic_event_loop_stop(void);

#endif /* CORE_QUIC_EVENT_LOOP_H */