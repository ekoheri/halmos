#ifndef HALMOS_CORE_QUIC_QUEUE_H
#define HALMOS_CORE_QUIC_QUEUE_H

#include "halmos_core_quic_conn_table.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>

typedef struct {
    uint8_t *data;
    size_t len;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    uint8_t dcid[MAX_DCID_LEN];
    uint8_t dcid_len;
    bool has_dcid;
    bool is_long_header;
} QuicPacketTask;

typedef struct QuicTaskNode {
    QuicPacketTask task;
    struct timeval arrival_time;
    struct QuicTaskNode *next;
} QuicTaskNode;

typedef struct {
    QuicTaskNode *head;
    QuicTaskNode *tail;
    int count;
    int max_queue_limit;
    int min_threads_limit;
    int max_threads_limit;
    int total_workers;
    _Atomic int active_workers;
    int scaling_in_progress;
    atomic_bool is_running;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t exit_cond;
} QuicTaskQueue;

/**
 * @brief Menginisialisasi antrean tugas QUIC menggunakan parameter adaptive_hw_aware.
 */
int core_quic_queue_init(void);

/**
 * @brief Menghentikan antrean, membebaskan sisa task, dan menghancurkan primitif sinkronisasi.
 */
void core_quic_queue_destroy(void);

/**
 * @brief Menandai antrean berhenti menerima tugas baru dan membangunkan worker yang menunggu.
 */
void core_quic_queue_stop(void);

/**
 * @brief Memasukkan paket QUIC ke antrean (thread-safe).
 *
 * @return 0 jika berhasil, -1 jika antrean penuh, -2 jika gagal alokasi memori / invalid argumen.
 */
int core_quic_queue_push(QuicTaskQueue *q, const uint8_t *data, size_t len,
                         const struct sockaddr_in *client_addr, socklen_t client_addr_len,
                         const uint8_t *dcid, uint8_t dcid_len,
                         bool has_dcid, bool is_long_header);

/**
 * @brief Mengambil satu tugas QUIC dari antrean (blocking/timedwait).
 *        Pemanggil bertanggung jawab membebaskan out_task->data dengan free().
 *
 * @return 0 jika berhasil mengambil task, -1 jika dihentikan/kosong, -2 jika argumen tidak valid.
 */
int core_quic_queue_pop(QuicTaskQueue *q, QuicPacketTask *out_task, struct timeval *out_arrival);

#endif /* HALMOS_CORE_QUIC_QUEUE_H */