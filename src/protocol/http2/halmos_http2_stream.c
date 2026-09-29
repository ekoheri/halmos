#include "halmos_http2_stream.h"
#include "halmos_http2_core.h"
#include "halmos_log.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>     // Untuk calloc, malloc, free
#include <string.h>     // Untuk strncpy
#include <sys/types.h>  // Untuk tipe data socket
#include <sys/socket.h> // Untuk struct sockaddr_storage, getpeername, AF_INET, AF_INET6
#include <netinet/in.h> // Untuk struct sockaddr_in, struct sockaddr_in6
#include <arpa/inet.h>  // Untuk inet_ntop

static uint32_t http2_stream_get_bucket_fibonacci(uint32_t stream_id);

HTTP2Stream* http2_stream_find_unlocked(HTTP2Session *session, uint32_t id) {
    if (!session || id == 0) return NULL;
    uint32_t bucket = http2_stream_get_bucket_fibonacci(id);
    HTTP2Stream *curr = session->streams_hash[bucket];
    while (curr != NULL) {
        if (curr->stream_id == id) {
            return curr;
        }
        curr = curr->node_next;
    }
    return NULL;
}
 
HTTP2Stream* http2_stream_find(HTTP2Session *session, uint32_t id) {
    if (!session) return NULL;
    pthread_mutex_lock(&session->streams_lock);
    HTTP2Stream *st = http2_stream_find_unlocked(session, id);
    pthread_mutex_unlock(&session->streams_lock);
    return st;
}

HTTP2Stream *http2_stream_get_or_create(HTTP2Session *session, uint32_t stream_id) {
    uint32_t bucket = http2_stream_get_bucket_fibonacci(stream_id);
    HTTP2Stream *st = NULL;

    pthread_mutex_lock(&session->streams_lock);
    
    HTTP2Stream *check = session->streams_hash[bucket];
    while (check != NULL) {
        if (check->stream_id == stream_id) {
            st = check;
            break;
        }
        check = check->node_next;
    }
 
    if (!st) {
        st = calloc(1, sizeof(HTTP2Stream));
        if (!st) {
            pthread_mutex_unlock(&session->streams_lock);
            write_log_error("[H2-ERROR] Malloc failed for new stream ID %u", stream_id);
            return NULL;
        }
        st->stream_id = stream_id;
        st->out_window_size = session->peer_initial_window_size; 
        st->file_fd = -1;            
        st->http1_compat.is_tls = session->is_tls;
 
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        
        strncpy(st->http1_compat.client_ip, "0.0.0.0", sizeof(st->http1_compat.client_ip) - 1);
        st->http1_compat.client_ip[sizeof(st->http1_compat.client_ip) - 1] = '\0';
        
        if (getpeername(session->fd, (struct sockaddr*)&addr, &addr_len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&addr;
                inet_ntop(AF_INET, &s->sin_addr, st->http1_compat.client_ip, sizeof(st->http1_compat.client_ip));
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
                inet_ntop(AF_INET6, &s->sin6_addr, st->http1_compat.client_ip, sizeof(st->http1_compat.client_ip));
            }
        }
 
        st->node_next = session->streams_hash[bucket];
        session->streams_hash[bucket] = st;
        session->active_stream_count++; 
    }
    pthread_mutex_unlock(&session->streams_lock);
    return st;
}

uint32_t http2_stream_get_bucket_fibonacci(uint32_t stream_id) {
    uint32_t hash = stream_id * HTTP2_GOLDEN_RATIO_32;
    return hash >> (32 - HTTP2_HASH_POWER);
}
 