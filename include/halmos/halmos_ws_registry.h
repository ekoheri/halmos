#ifndef HALMOS_WS_REGISTRY_H
#define HALMOS_WS_REGISTRY_H

#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/ssl.h>

#define MAX_WS_CLIENTS 1024
#ifndef MAX_FDS
#define MAX_FDS 65536
#endif
#define HASH_SIZE 256
#define USER_HASH_SIZE 256
#define MAX_TOPICS_PER_USER 16

typedef struct HalmosWSClient {
    int fd;
    SSL *ssl;
    time_t last_seen;
    bool is_active;
    
    // Multi-protocol / H2 metadata
    bool is_http2;
    uint32_t stream_id;
    
    // Identity & Session
    uint64_t session_id;
    char user_id[64];
    
    // Pub/Sub Topics
    char subscribed_topics[MAX_TOPICS_PER_USER][128];
    int topic_count;

    pthread_mutex_t client_lock;
} HalmosWSClient;

typedef struct ws_subscriber {
    HalmosWSClient *client;
    struct ws_subscriber *next;
} ws_subscriber_t;

typedef struct {
    char topic_name[128];
    ws_subscriber_t *head;
    pthread_mutex_t topic_lock;
} ws_topic_bucket_t;

typedef struct ws_user_node {
    char *user_id;
    HalmosWSClient *client;
    struct ws_user_node *next;
} ws_user_node_t;

/* 
 * =============================================================================
 * LOCK HIERARCHY (Mencegah Deadlock)
 * =============================================================================
 * Selalu ambil mutex berdasarkan urutan hierarki dari atas ke bawah:
 * 
 *   1. registry.registry_lock   (Global lock untuk pool clients & fd_map)
 *        │
 *        ├──> 2. registry.hash_lock      (Topic buckets)
 *        │      │
 *        │      └──> 3. bucket->topic_lock
 *        │
 *        └──> 4. registry.user_map_lock  (User-to-Client hash mappings)
 *               │
 *               └──> 5. client->client_lock (Read/Write lock per individual client)
 * 
 * ATURAN STRICT: Dilarang mengambil mutex level atas jika sedang memegang
 * mutex level di bawahnya!
 * =============================================================================
 */
typedef struct {
    HalmosWSClient *clients[MAX_WS_CLIENTS];
    HalmosWSClient *fd_map[MAX_FDS]; // Direct Mapping O(1) untuk Instant Lookup
    int current_count;
    
    pthread_mutex_t registry_lock; 
    pthread_mutex_t hash_lock;     // Lock khusus Topic Buckets
    pthread_mutex_t user_map_lock; // Lock khusus User Mapping
    
    ws_topic_bucket_t *buckets[HASH_SIZE];
    ws_user_node_t *user_map[USER_HASH_SIZE];
} HalmosWSRegistry;

void ws_registry_init(void);
void ws_registry_destroy(void);

int ws_registry_add(int fd, SSL *ssl);
int ws_registry_add_h2(int fd, SSL *ssl, uint32_t stream_id);
void ws_registry_remove(int fd);

void ws_registry_get_h2_status(int fd, bool *out_is_http2, uint32_t *out_stream_id);
void ws_registry_update_activity(int fd);
const char* ws_registry_get_user_id(int fd);

void ws_registry_heartbeat(void);
void ws_registry_reaper(void);

void ws_registry_add_to_topic(int fd, const char *app_id, const char *topic);
void ws_registry_publish(const char *app_id, const char *topic, const char *message);
void ws_registry_broadcast(const char *message);

void ws_registry_set_user_id(int fd, const char *user_id);
int ws_registry_get_fd_by_name(const char *name);
bool ws_registry_get_session_info(const char *name, int *out_fd, uint64_t *out_session, SSL **out_ssl);
bool ws_registry_validate_session(int fd, uint64_t session_id);

#endif