#include "halmos_ws_registry.h"
#include "halmos_ws_system.h"
#include "halmos_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

static HalmosWSRegistry registry;

/* IMPORTANT: Counter ini dilindungi secara eksklusif oleh registry.registry_lock
 * pada fungsi ws_registry_add dan ws_registry_add_h2. JANGAN diakses di luar lock! */
static uint64_t global_session_counter = 1;

static inline bool ws_fd_is_valid(int fd) {
    return (fd >= 0 && fd < MAX_FDS);
}

static void ws_registry_send_text(int fd, SSL *ssl, const char *message);
static void ws_registry_send_ping(int fd, SSL *ssl);
static unsigned long hash_topic(const char *str);
static size_t ws_system_build_frame(unsigned char *out_frame, const char *message, size_t len);

/* Helper internal: Direct lookup O(1) berdasarkan FD (Unsafe: panggil dengan lock) */
static inline HalmosWSClient* ws_registry_find_by_fd_unlocked(int fd) {
    if (!ws_fd_is_valid(fd)) return NULL;
    return registry.fd_map[fd];
}

/* =================================================================================
 * BLOK 1: Cluster Manajemen Koneksi
 * ================================================================================= */

void ws_registry_init(void) {
    pthread_mutex_init(&registry.registry_lock, NULL);
    pthread_mutex_init(&registry.hash_lock, NULL);
    pthread_mutex_init(&registry.user_map_lock, NULL);
    registry.current_count = 0;
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        registry.clients[i] = NULL;
    }
    for (int i = 0; i < MAX_FDS; i++) {
        registry.fd_map[i] = NULL;
    }
    for (int i = 0; i < HASH_SIZE; i++) {
        registry.buckets[i] = NULL;
    }
    for (int i = 0; i < USER_HASH_SIZE; i++) {
        registry.user_map[i] = NULL;
    }
}

int ws_registry_add(int fd, SSL *ssl) {
    if (!ws_fd_is_valid(fd)) return -1;

    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i] == NULL) {
            HalmosWSClient *new_client = (HalmosWSClient *)calloc(1, sizeof(HalmosWSClient));
            if (!new_client) {
                pthread_mutex_unlock(&registry.registry_lock);
                return -1;
            }
            
            new_client->fd = fd;
            new_client->ssl = ssl;
            new_client->last_seen = time(NULL);
            new_client->is_active = true;
            new_client->topic_count = 0;
            new_client->is_http2 = false;
            new_client->stream_id = 0;

            new_client->session_id = ((uint64_t)time(NULL) << 32) | global_session_counter++;
            pthread_mutex_init(&new_client->client_lock, NULL);
            
            registry.clients[i] = new_client;
            registry.fd_map[fd] = new_client; // Instant Lookup Mapping O(1)
            registry.current_count++;
            
            pthread_mutex_unlock(&registry.registry_lock);
            return i;
        }
    }
    
    pthread_mutex_unlock(&registry.registry_lock);
    return -1;
}

int ws_registry_add_h2(int fd, SSL *ssl, uint32_t stream_id) {
    if (!ws_fd_is_valid(fd)) return -1;

    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i] == NULL) {
            HalmosWSClient *new_client = (HalmosWSClient *)calloc(1, sizeof(HalmosWSClient));
            if (!new_client) {
                pthread_mutex_unlock(&registry.registry_lock);
                return -1;
            }
            
            new_client->fd = fd;
            new_client->ssl = ssl;
            new_client->last_seen = time(NULL);
            new_client->is_active = true;
            new_client->topic_count = 0;
            new_client->is_http2 = true;
            new_client->stream_id = stream_id;

            new_client->session_id = ((uint64_t)time(NULL) << 32) | global_session_counter++;
            pthread_mutex_init(&new_client->client_lock, NULL);
            
            registry.clients[i] = new_client;
            registry.fd_map[fd] = new_client; // Instant Lookup Mapping O(1)
            registry.current_count++;
            
            pthread_mutex_unlock(&registry.registry_lock);
            return i;
        }
    }
    
    pthread_mutex_unlock(&registry.registry_lock);
    return -1;
}

void ws_registry_get_h2_status(int fd, bool *out_is_http2, uint32_t *out_stream_id) {
    if (!ws_fd_is_valid(fd)) {
        if (out_is_http2) *out_is_http2 = false;
        if (out_stream_id) *out_stream_id = 0;
        return;
    }

    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (c != NULL && c->is_active) {
        *out_is_http2 = c->is_http2;
        *out_stream_id = c->stream_id;
        pthread_mutex_unlock(&registry.registry_lock);
        return;
    }
    
    *out_is_http2 = false;
    *out_stream_id = 0;
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_remove(int fd) {
    if (!ws_fd_is_valid(fd)) return;

    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd);
    if (c) {
        pthread_mutex_lock(&c->client_lock);
        c->is_active = false;
        pthread_mutex_unlock(&c->client_lock);

        /* 1. Cabut dari USER_MAP Hash Table (Memakai user_map_lock terpisah) */
        if (strlen(c->user_id) > 0) {
            pthread_mutex_lock(&registry.user_map_lock);
            unsigned long u_idx = hash_topic(c->user_id) % USER_HASH_SIZE;
            ws_user_node_t **upp = &registry.user_map[u_idx];
            while (*upp) {
                if ((*upp)->client == c) {
                    ws_user_node_t *u_trash = *upp;
                    *upp = (*upp)->next;
                    free(u_trash);
                    break;
                }
                upp = &((*upp)->next);
            }
            pthread_mutex_unlock(&registry.user_map_lock);
        }

        /* 2. Cabut dari semua topic bucket di Hash Table */
        pthread_mutex_lock(&registry.hash_lock);
        for (int j = 0; j < c->topic_count; j++) {
            unsigned long idx = hash_topic(c->subscribed_topics[j]);
            ws_topic_bucket_t *b = registry.buckets[idx];
            if (b) {
                pthread_mutex_lock(&b->topic_lock);
                ws_subscriber_t **pp = &b->head;
                while (*pp) {
                    if ((*pp)->client == c) {
                        ws_subscriber_t *trash = *pp;
                        *pp = (*pp)->next;
                        free(trash);
                        break;
                    }
                    pp = &((*pp)->next);
                }
                pthread_mutex_unlock(&b->topic_lock);
            }
        }
        pthread_mutex_unlock(&registry.hash_lock);

        /* 3. Kosongkan slot clients[], fd_map[] & Bebaskan memori */
        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (registry.clients[i] == c) {
                registry.clients[i] = NULL;
                break;
            }
        }
        registry.fd_map[fd] = NULL;
        registry.current_count--;

        pthread_mutex_destroy(&c->client_lock);
        free(c);
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_broadcast(const char *message) {
    size_t msg_len = strlen(message);
    unsigned char frame[65535]; 
    size_t frame_len = ws_system_build_frame(frame, message, msg_len); 

    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            if (pthread_mutex_trylock(&c->client_lock) == 0) {
                if (c->is_active) {
                    if (c->is_http2) {
                        ws_system_send_text_h2(c->fd, c->stream_id, message, NULL);
                    } else {
                        if (c->ssl) {
                            SSL_write(c->ssl, frame, (int)frame_len);
                        } else {
                            send(c->fd, frame, frame_len, MSG_NOSIGNAL);
                        }
                    }
                }
                pthread_mutex_unlock(&c->client_lock);
            }
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_destroy(void) {
    pthread_mutex_lock(&registry.registry_lock);
    pthread_mutex_lock(&registry.hash_lock);
    pthread_mutex_lock(&registry.user_map_lock);

    for (int i = 0; i < HASH_SIZE; i++) {
        if (registry.buckets[i]) {
            ws_subscriber_t *sub = registry.buckets[i]->head;
            while (sub) {
                ws_subscriber_t *tmp = sub;
                sub = sub->next;
                free(tmp);
            }
            pthread_mutex_destroy(&registry.buckets[i]->topic_lock);
            free(registry.buckets[i]);
            registry.buckets[i] = NULL;
        }
    }

    for (int i = 0; i < USER_HASH_SIZE; i++) {
        ws_user_node_t *curr = registry.user_map[i];
        while (curr) {
            ws_user_node_t *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
        registry.user_map[i] = NULL;
    }

    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i]) {
            pthread_mutex_destroy(&registry.clients[i]->client_lock);
            free(registry.clients[i]);
            registry.clients[i] = NULL;
        }
    }
    for (int i = 0; i < MAX_FDS; i++) {
        registry.fd_map[i] = NULL;
    }

    pthread_mutex_unlock(&registry.user_map_lock);
    pthread_mutex_unlock(&registry.hash_lock);
    pthread_mutex_unlock(&registry.registry_lock);

    pthread_mutex_destroy(&registry.user_map_lock);
    pthread_mutex_destroy(&registry.hash_lock);
    pthread_mutex_destroy(&registry.registry_lock);
}

/* =================================================================================
 * BLOK 2: Cluster Maintenance & Health
 * ================================================================================= */

void ws_registry_update_activity(int fd) {
    if (!ws_fd_is_valid(fd)) return;

    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (c != NULL) {
        c->last_seen = time(NULL);
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_heartbeat(void) {
    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            pthread_mutex_lock(&c->client_lock);
            if (c->is_active && !c->is_http2) {
                ws_registry_send_ping(c->fd, c->ssl);
            }
            pthread_mutex_unlock(&c->client_lock);
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_reaper(void) {
    time_t now = time(NULL);
    int timeout_limit = 90; 
    int dead_fds[MAX_WS_CLIENTS];
    int dead_count = 0;

    pthread_mutex_lock(&registry.registry_lock);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            if (difftime(now, c->last_seen) > timeout_limit) {
                dead_fds[dead_count++] = c->fd;
            }
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);

    for (int i = 0; i < dead_count; i++) {
        write_log("[REAPER] Cleaning up ghost connection: FD %d", dead_fds[i]);
        close(dead_fds[i]);
        ws_registry_remove(dead_fds[i]);
    }
}

/* =================================================================================
 * BLOK 3: Cluster Pub/Sub & User Identity
 * ================================================================================= */

void ws_registry_add_to_topic(int fd, const char *app_id, const char *topic) {
    if (!ws_fd_is_valid(fd)) return;

    char full_key[64];
    snprintf(full_key, sizeof(full_key), "%.30s:%.32s", app_id, topic);
    unsigned long idx = hash_topic(full_key);

    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *target_client = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (!target_client || !target_client->is_active) {
        pthread_mutex_unlock(&registry.registry_lock);
        return;
    }
    pthread_mutex_unlock(&registry.registry_lock);

    /* 1. Kelola Bucket di Hash Table */
    pthread_mutex_lock(&registry.hash_lock);
    ws_topic_bucket_t *b = registry.buckets[idx];
    if (!b) {
        b = (ws_topic_bucket_t *)calloc(1, sizeof(ws_topic_bucket_t));
        snprintf(b->topic_name, sizeof(b->topic_name), "%s", full_key);
        pthread_mutex_init(&b->topic_lock, NULL);
        registry.buckets[idx] = b;
    }
    pthread_mutex_unlock(&registry.hash_lock);

    /* 2. Deduplikasi Subscription */
    pthread_mutex_lock(&b->topic_lock);
    ws_subscriber_t *curr = b->head;
    while (curr) {
        if (curr->client == target_client) {
            pthread_mutex_unlock(&b->topic_lock);
            return;
        }
        curr = curr->next;
    }

    ws_subscriber_t *sub = (ws_subscriber_t *)malloc(sizeof(ws_subscriber_t));
    sub->client = target_client;
    sub->next = b->head;
    b->head = sub;
    pthread_mutex_unlock(&b->topic_lock);

    /* 3. Catat Metadata di Client */
    pthread_mutex_lock(&target_client->client_lock);
    if (target_client->topic_count < MAX_TOPICS_PER_USER) {
        memcpy(target_client->subscribed_topics[target_client->topic_count], 
               full_key, 
               sizeof(full_key));
        target_client->topic_count++;
    }
    pthread_mutex_unlock(&target_client->client_lock);
}

void ws_registry_publish(const char *app_id, const char *topic, const char *message) {
    char full_key[128];
    snprintf(full_key, sizeof(full_key), "%s:%s", app_id, topic);
    unsigned long idx = hash_topic(full_key);

    pthread_mutex_lock(&registry.hash_lock);
    ws_topic_bucket_t *b = registry.buckets[idx];
    pthread_mutex_unlock(&registry.hash_lock);

    if (!b) return;

    pthread_mutex_lock(&b->topic_lock);
    ws_subscriber_t *curr = b->head;
    
    while (curr) {
        HalmosWSClient *c = curr->client;
        if (c && c->is_active) {
            pthread_mutex_lock(&c->client_lock);
            if (c->is_active) {
                if (c->is_http2) {
                    ws_system_send_text_h2(c->fd, c->stream_id, message, NULL);
                } else {
                    ws_registry_send_text(c->fd, c->ssl, message);
                }
            }
            pthread_mutex_unlock(&c->client_lock);
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&b->topic_lock);
}

void ws_registry_set_user_id(int fd, const char *user_id) {
    if (!ws_fd_is_valid(fd)) return;

    if (!user_id || strlen(user_id) == 0) return;

    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (c && c->is_active) {
        pthread_mutex_lock(&registry.user_map_lock);
        
        /* Cleanup node user_id lama jika ada */
        if (strlen(c->user_id) > 0) {
            unsigned long old_idx = hash_topic(c->user_id) % USER_HASH_SIZE;
            ws_user_node_t **upp = &registry.user_map[old_idx];
            while (*upp) {
                if ((*upp)->client == c) {
                    ws_user_node_t *trash = *upp;
                    *upp = (*upp)->next;
                    free(trash);
                    break;
                }
                upp = &((*upp)->next);
            }
        }

        /* Update user_id di struct client */
        strncpy(c->user_id, user_id, 63);
        c->user_id[63] = '\0';

        /* Masukkan ke user_map hash table */
        unsigned long idx = hash_topic(user_id) % USER_HASH_SIZE;
        ws_user_node_t *new_node = (ws_user_node_t *)malloc(sizeof(ws_user_node_t));
        new_node->user_id = c->user_id; // Safe lifetime pointer
        new_node->client = c;
        new_node->next = registry.user_map[idx];
        registry.user_map[idx] = new_node;

        pthread_mutex_unlock(&registry.user_map_lock);
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

int ws_registry_get_fd_by_name(const char *name) {
    int fd = -1;
    if (ws_registry_get_session_info(name, &fd, NULL, NULL)) {
        return fd;
    }
    return -1;
}

const char* ws_registry_get_user_id(int fd) {
    if (!ws_fd_is_valid(fd)) return NULL;

    const char *uid = NULL;
    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (c && c->is_active) {
        uid = c->user_id;
    }
    pthread_mutex_unlock(&registry.registry_lock);
    return uid;
}

bool ws_registry_get_session_info(const char *name, int *out_fd, uint64_t *out_session, SSL **out_ssl) {
    if (!name) return false;

    unsigned long idx = hash_topic(name) % USER_HASH_SIZE;

    pthread_mutex_lock(&registry.user_map_lock);
    ws_user_node_t *node = registry.user_map[idx];
    while (node) {
        if (node->client && node->client->is_active && strcmp(node->client->user_id, name) == 0) {
            if (out_fd) *out_fd = node->client->fd;
            if (out_session) *out_session = node->client->session_id;
            if (out_ssl) *out_ssl = node->client->ssl;
            
            pthread_mutex_unlock(&registry.user_map_lock);
            return true;
        }
        node = node->next;
    }
    pthread_mutex_unlock(&registry.user_map_lock);
    return false;
}

bool ws_registry_validate_session(int fd, uint64_t session_id) {
    if (!ws_fd_is_valid(fd)) return false;
    
    pthread_mutex_lock(&registry.registry_lock);
    HalmosWSClient *c = ws_registry_find_by_fd_unlocked(fd); // O(1) Direct Lookup
    if (c && c->session_id == session_id && c->is_active) {
        pthread_mutex_unlock(&registry.registry_lock);
        return true;
    }
    pthread_mutex_unlock(&registry.registry_lock);
    return false;
}

/* =================================================================================
 * BLOK 4: Cluster Low-Level Driver
 * ================================================================================= */

static void ws_registry_send_ping(int fd, SSL *ssl) {
    unsigned char frame[2] = {0x89, 0x00};

    if (ssl) {
        SSL_write(ssl, frame, 2);
    } else {
        send(fd, frame, 2, MSG_NOSIGNAL);
    }
}

static void ws_registry_send_text(int fd, SSL *ssl, const char *message) {
    size_t len = strlen(message);
    unsigned char frame[4096];
    int frame_header_len = 0;

    frame[0] = 0x81; 

    if (len <= 125) {
        frame[1] = (unsigned char)len;
        frame_header_len = 2;
    } else if (len <= 65535) {
        frame[1] = 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
        frame_header_len = 4;
    } else {
        return; 
    }

    memcpy(frame + frame_header_len, message, len);
    size_t total_len = frame_header_len + len;

    if (ssl) {
        SSL_write(ssl, frame, (int)total_len);
    } else {
        send(fd, frame, total_len, MSG_NOSIGNAL);
    }
}

static unsigned long hash_topic(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; 
    return hash % HASH_SIZE;
}

static size_t ws_system_build_frame(unsigned char *out_frame, const char *message, size_t len) {
    size_t header_len = 0;

    out_frame[0] = 0x81; 

    if (len <= 125) {
        out_frame[1] = (unsigned char)len;
        header_len = 2;
    } else if (len <= 65535) {
        out_frame[1] = 126;
        out_frame[2] = (len >> 8) & 0xFF;
        out_frame[3] = len & 0xFF;
        header_len = 4;
    } else {
        return 0; 
    }

    memcpy(out_frame + header_len, message, len);
    return header_len + len;
}