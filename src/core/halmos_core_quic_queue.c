#include "halmos_core_quic_queue.h"
#include "halmos_global.h"
#include "halmos_core_adaptive.h"
#include "halmos_core_config.h"
#include "halmos_core_quic_thread_pool.h"
#include "halmos_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

QuicTaskQueue quic_global_queue;

int core_quic_queue_init(void) {
    quic_global_queue.head = quic_global_queue.tail = NULL;
    quic_global_queue.count = 0;
    quic_global_queue.max_queue_limit = adaptive_hw_aware.core_queue_capacity;
    quic_global_queue.active_workers = 0;
    quic_global_queue.total_workers = adaptive_hw_aware.worker_min;
    quic_global_queue.min_threads_limit = adaptive_hw_aware.worker_min;
    quic_global_queue.max_threads_limit = adaptive_hw_aware.worker_max;
    quic_global_queue.scaling_in_progress = 0;
    atomic_store(&quic_global_queue.is_running, true);

    if (pthread_mutex_init(&quic_global_queue.lock, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&quic_global_queue.cond, NULL) != 0) {
        pthread_mutex_destroy(&quic_global_queue.lock);
        return -1;
    }
    if (pthread_cond_init(&quic_global_queue.exit_cond, NULL) != 0) {
        pthread_cond_destroy(&quic_global_queue.cond);
        pthread_mutex_destroy(&quic_global_queue.lock);
        return -1;
    }

    return 0;
}

void core_quic_queue_destroy(void) {
    pthread_mutex_lock(&quic_global_queue.lock);
    QuicTaskNode *curr = quic_global_queue.head;
    quic_global_queue.head = quic_global_queue.tail = NULL;
    quic_global_queue.count = 0;
    pthread_mutex_unlock(&quic_global_queue.lock);

    while (curr) {
        QuicTaskNode *tmp = curr;
        curr = curr->next;
        if (tmp->task.data) {
            free(tmp->task.data);
        }
        free(tmp);
    }

    pthread_mutex_destroy(&quic_global_queue.lock);
    pthread_cond_destroy(&quic_global_queue.cond);
    pthread_cond_destroy(&quic_global_queue.exit_cond);
}

void core_quic_queue_stop(void) {
    pthread_mutex_lock(&quic_global_queue.lock);
    atomic_store(&quic_global_queue.is_running, false);
    pthread_cond_broadcast(&quic_global_queue.cond);
    pthread_mutex_unlock(&quic_global_queue.lock);
}

int core_quic_queue_push(QuicTaskQueue *q, const uint8_t *data, size_t len,
                         const struct sockaddr_in *client_addr, socklen_t client_addr_len,
                         const uint8_t *dcid, uint8_t dcid_len,
                         bool has_dcid, bool is_long_header) {
    if (!q || !data || len == 0 || !client_addr) {
        return -2;
    }

    pthread_mutex_lock(&q->lock);

    if (q->count >= q->max_queue_limit) {
        pthread_mutex_unlock(&q->lock);
        write_log("[QUIC QUEUE WARNING] Queue capacity reached limit.");
        return -1;
    }

    QuicTaskNode *new_node = malloc(sizeof(QuicTaskNode));
    if (!new_node) {
        pthread_mutex_unlock(&q->lock);
        return -2;
    }

    new_node->task.data = malloc(len);
    if (!new_node->task.data) {
        free(new_node);
        pthread_mutex_unlock(&q->lock);
        return -2;
    }
    memcpy(new_node->task.data, data, len);
    new_node->task.len = len;

    memcpy(&new_node->task.client_addr, client_addr, sizeof(struct sockaddr_in));
    new_node->task.client_addr_len = client_addr_len;
    new_node->task.has_dcid = has_dcid;
    new_node->task.is_long_header = is_long_header;

    if (has_dcid && dcid_len > 0 && dcid_len <= MAX_DCID_LEN) {
        memcpy(new_node->task.dcid, dcid, dcid_len);
        new_node->task.dcid_len = dcid_len;
    } else {
        new_node->task.dcid_len = 0;
    }

    gettimeofday(&new_node->arrival_time, NULL);
    new_node->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    q->count++;

    AdaptivePolicy policy = core_adaptive_get_policy();
    int queue_threshold = (int)((double)q->max_queue_limit * policy.threshold_ratio);
    int spawn_count = 0;

    if (q->count > queue_threshold &&
        q->total_workers < q->max_threads_limit &&
        !q->scaling_in_progress) {

        int available_slots = q->max_threads_limit - q->total_workers;
        int spawn_step = policy.spawn_step;

        spawn_count = (available_slots < spawn_step) ? available_slots : spawn_step;
        q->total_workers += spawn_count;
        q->scaling_in_progress = 1;
    }

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);

    if (spawn_count > 0) {
        int actually_spawned = core_quic_thread_pool_spawn_workers(spawn_count);

        pthread_mutex_lock(&q->lock);
        if (actually_spawned < spawn_count) {
            q->total_workers -= (spawn_count - actually_spawned);
        }
        q->scaling_in_progress = 0;
        pthread_mutex_unlock(&q->lock);
    }

    return 0;
}

int core_quic_queue_pop(QuicTaskQueue *q, QuicPacketTask *out_task, struct timeval *out_arrival) {
    if (!q || !out_task) {
        return -2;
    }

    pthread_mutex_lock(&q->lock);

    struct timespec ts;
    struct timeval now;

    while (q->head == NULL) {
        if (!atomic_load(&q->is_running)) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -1;
        }

        gettimeofday(&now, NULL);
        AdaptivePolicy policy = core_adaptive_get_policy();
        int current_timeout = policy.timeout_idle;

        ts.tv_sec = now.tv_sec + current_timeout;
        ts.tv_nsec = now.tv_usec * 1000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);

        if (!atomic_load(&q->is_running) && q->head == NULL) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -1;
        }

        if (rc == ETIMEDOUT &&
            q->head == NULL &&
            q->total_workers > q->min_threads_limit &&
            atomic_load(&q->is_running)) {
            q->total_workers--;
            pthread_cond_signal(&q->exit_cond);
            pthread_mutex_unlock(&q->lock);
            return -1;
        }
    }

    QuicTaskNode *tmp = q->head;

    *out_task = tmp->task;
    if (out_arrival) {
        *out_arrival = tmp->arrival_time;
    }

    q->head = q->head->next;
    if (q->head == NULL) {
        q->tail = NULL;
    }
    q->count--;

    atomic_fetch_add(&q->active_workers, 1);
    free(tmp);

    pthread_mutex_unlock(&q->lock);
    return 0;
}