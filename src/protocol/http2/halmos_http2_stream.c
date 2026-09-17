#include "halmos_http2_stream.h"
#include "halmos_http2_core.h"

#include <stdint.h>
#include <stdbool.h>


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

uint32_t http2_stream_get_bucket_fibonacci(uint32_t stream_id) {
    uint32_t hash = stream_id * HTTP2_GOLDEN_RATIO_32;
    return hash >> (32 - HTTP2_HASH_POWER);
}
 