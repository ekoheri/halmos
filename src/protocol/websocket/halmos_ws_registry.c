#include "halmos_ws_registry.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h> // Buat fungsi send() dan MSG_NOSIGNAL
#include <unistd.h>     // Buat fungsi close() jika nanti butuh
#include <errno.h>      // Selalu bagus buat jaga-jaga ngecek error

// Instance global buku alamat
static HalmosWSRegistry registry;

static void halmos_ws_send_text(int fd, SSL *ssl, const char *message);

static void halmos_ws_send_ping(int fd, SSL *ssl);

static unsigned long hash_topic(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; 
    return hash % HASH_SIZE;
}

void ws_registry_init() {
    pthread_mutex_init(&registry.registry_lock, NULL);
    pthread_mutex_init(&registry.hash_lock, NULL); // Inisialisasi lock hash table
    registry.current_count = 0;
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        registry.clients[i] = NULL;
    }
    for (int i = 0; i < HASH_SIZE; i++) {
        registry.buckets[i] = NULL;
    }
}

int ws_registry_add(int fd, SSL *ssl) {
    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i] == NULL) {
            HalmosWSClient *new_client = (HalmosWSClient *)malloc(sizeof(HalmosWSClient));
            if (!new_client) {
                pthread_mutex_unlock(&registry.registry_lock);
                return -1;
            }
            
            new_client->fd = fd;
            new_client->ssl = ssl;
            new_client->last_seen = time(NULL);
            new_client->is_active = true;
            new_client->topic_count = 0; // Pastikan counter topik mulai dari nol
            pthread_mutex_init(&new_client->client_lock, NULL);
            
            registry.clients[i] = new_client;
            registry.current_count++;
            
            pthread_mutex_unlock(&registry.registry_lock);
            return i;
        }
    }
    
    pthread_mutex_unlock(&registry.registry_lock);
    return -1;
}

void ws_registry_remove(int fd) {
    pthread_mutex_lock(&registry.registry_lock);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c && c->fd == fd) {
            
            // 1. Cabut dari semua grup di Hash Table (Gunakan catatan internal client)
            pthread_mutex_lock(&registry.hash_lock);
            for (int j = 0; j < c->topic_count; j++) {
                unsigned long idx = hash_topic(c->subscribed_topics[j]);
                ws_topic_bucket_t *b = registry.buckets[idx];
                if (b) {
                    pthread_mutex_lock(&b->topic_lock);
                    ws_subscriber_t **pp = &b->head;
                    while (*pp) {
                        if ((*pp)->fd == fd) {
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

            // 2. Hapus dari Array Utama dan Bebaskan Memori
            pthread_mutex_destroy(&c->client_lock);
            free(c);
            registry.clients[i] = NULL;
            registry.current_count--;
            break;
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_update_activity(int fd) {
    // Kita tidak pakai lock global di sini biar kencang, 
    // karena cuma update timestamp (atomic-ish pada OS modern)
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i] != NULL && registry.clients[i]->fd == fd) {
            registry.clients[i]->last_seen = time(NULL);
            break;
        }
    }
}

void ws_registry_broadcast(const char *message) {
    pthread_mutex_lock(&registry.registry_lock);
    
    //int len = strlen(message);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            
            // Kunci client-nya biar nggak tabrakan sama thread lain yang mau nulis
            pthread_mutex_lock(&c->client_lock);
            
            // Di sini nanti panggil fungsi pembungkus frame WS lu
            halmos_ws_send_text(c->fd, c->ssl, message);
            pthread_mutex_unlock(&c->client_lock);
        }
    }
    
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_heartbeat() {
    pthread_mutex_lock(&registry.registry_lock);
    
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            pthread_mutex_lock(&c->client_lock);
            
            // Kirim detak jantung
            halmos_ws_send_ping(c->fd, c->ssl);
            
            pthread_mutex_unlock(&c->client_lock);
        }
    }
    
    pthread_mutex_unlock(&registry.registry_lock);
    // printf("[WS-HEARTBEAT] PING dikirim ke semua client.\n");
}

// Di halmos_ws_registry.c

void ws_registry_reaper() {
    time_t now = time(NULL);
    int timeout_limit = 90; 

    pthread_mutex_lock(&registry.registry_lock);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            if (difftime(now, c->last_seen) > timeout_limit) {
                int dead_fd = c->fd;
                // Lepas lock global agar ws_registry_remove bisa bekerja tanpa deadlock
                pthread_mutex_unlock(&registry.registry_lock); 
                close(dead_fd);
                ws_registry_remove(dead_fd); 
                pthread_mutex_lock(&registry.registry_lock);
            }
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_add_to_topic(int fd, const char *app_id, const char *topic) {
    char full_key[128];
    snprintf(full_key, sizeof(full_key), "%s:%s", app_id, topic);
    unsigned long idx = hash_topic(full_key);

    // 1. Kelola Bucket di Hash Table
    pthread_mutex_lock(&registry.hash_lock);
    ws_topic_bucket_t *b = registry.buckets[idx];
    if (!b) {
        b = (ws_topic_bucket_t *)calloc(1, sizeof(ws_topic_bucket_t));
        //strncpy(b->topic_name, full_key, 127);
        strncpy(b->topic_name, full_key, sizeof(b->topic_name) - 1);
        b->topic_name[sizeof(b->topic_name) - 1] = '\0';
        pthread_mutex_init(&b->topic_lock, NULL);
        registry.buckets[idx] = b;
    }
    pthread_mutex_unlock(&registry.hash_lock);

    // 2. Tambahkan ke list subscriber topik tersebut
    pthread_mutex_lock(&b->topic_lock);
    ws_subscriber_t *sub = (ws_subscriber_t *)malloc(sizeof(ws_subscriber_t));
    sub->fd = fd;
    sub->next = b->head;
    b->head = sub;
    pthread_mutex_unlock(&b->topic_lock);

    // 3. Catat di metadata client untuk mempermudah pembersihan
    pthread_mutex_lock(&registry.registry_lock);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i] && registry.clients[i]->fd == fd) {
            if (registry.clients[i]->topic_count < MAX_TOPICS_PER_USER) {
                // Ambil pointer tujuan biar kode lebih bersih
                char *dest = registry.clients[i]->subscribed_topics[registry.clients[i]->topic_count];
                
                // Gunakan sizeof dari array tujuan, jangan pakai angka manual 63
                strncpy(dest, full_key, 64 - 1); 
                dest[64 - 1] = '\0'; // Pastikan aman!
                
                registry.clients[i]->topic_count++;
            }
            break;
        }
    }
    pthread_mutex_unlock(&registry.registry_lock);
}

void ws_registry_publish(const char *app_id, const char *topic, const char *message) {
    char full_key[128];
    snprintf(full_key, sizeof(full_key), "%s:%s", app_id, topic);
    unsigned long idx = hash_topic(full_key);

    ws_topic_bucket_t *b = registry.buckets[idx];
    if (!b) return;

    pthread_mutex_lock(&b->topic_lock);
    ws_subscriber_t *curr = b->head;
    while (curr) {
        // Cari SSL context di array utama untuk pengiriman data
        pthread_mutex_lock(&registry.registry_lock);
        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (registry.clients[i] && registry.clients[i]->fd == curr->fd) {
                pthread_mutex_lock(&registry.clients[i]->client_lock);
                halmos_ws_send_text(registry.clients[i]->fd, registry.clients[i]->ssl, message);
                pthread_mutex_unlock(&registry.clients[i]->client_lock);
                break;
            }
        }
        pthread_mutex_unlock(&registry.registry_lock);
        curr = curr->next;
    }
    pthread_mutex_unlock(&b->topic_lock);
}

void ws_registry_destroy() {
    pthread_mutex_lock(&registry.registry_lock);
    // Bersihkan Client Array
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (registry.clients[i]) {
            pthread_mutex_destroy(&registry.clients[i]->client_lock);
            free(registry.clients[i]);
            registry.clients[i] = NULL;
        }
    }
    
    // Bersihkan Hash Table
    pthread_mutex_lock(&registry.hash_lock);
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
    pthread_mutex_unlock(&registry.hash_lock);
    
    pthread_mutex_unlock(&registry.registry_lock);
    pthread_mutex_destroy(&registry.registry_lock);
    pthread_mutex_destroy(&registry.hash_lock);
}

// FUNGSI HELPER

void halmos_ws_send_ping(int fd, SSL *ssl) {
    unsigned char frame[2];
    frame[0] = 0x89; // FIN bit set + Opcode 0x9 (PING)
    frame[1] = 0x00; // Payload length 0 (Ping biasanya kosong)

    if (ssl) {
        SSL_write(ssl, frame, 2);
    } else {
        send(fd, frame, 2, MSG_NOSIGNAL);
    }
}

void halmos_ws_send_text(int fd, SSL *ssl, const char *message) {
    size_t len = strlen(message);
    unsigned char frame[4096]; // Buffer sementara untuk frame
    int frame_header_len = 0;

    // 1. Set Header Dasar (FIN = 1, Opcode = 0x1 untuk Text)
    frame[0] = 0x81; 

    // 2. Set Payload Length
    if (len <= 125) {
        frame[1] = (unsigned char)len;
        frame_header_len = 2;
    } else if (len <= 65535) {
        frame[1] = 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
        frame_header_len = 4;
    }
    // (Untuk pesan > 65KB kita abaikan dulu biar simpel)

    // 3. Gabungkan Header + Isi Pesan
    memcpy(frame + frame_header_len, message, len);
    size_t total_len = frame_header_len + len;

    // 4. Kirim lewat jalur yang benar (WSS vs WS)
    if (ssl) {
        SSL_write(ssl, frame, total_len);
    } else {
        send(fd, frame, total_len, MSG_NOSIGNAL);
    }
}

//Fungsi debug aja

/*void ws_registry_show() {
    pthread_mutex_lock(&registry.registry_lock);
    
    printf("\n"
           "====================================================\n"
           "       HALMOS WS REGISTRY (BUKU ALAMAT)             \n"
           "====================================================\n"
           " TOTAL CLIENT AKTIF: %d\n"
           "----------------------------------------------------\n"
           " SLOT | FD  | MODE | LAST SEEN (sec ago) | STATUS   \n"
           "----------------------------------------------------\n", 
           registry.current_count);

    time_t now = time(NULL);
    int found = 0;

    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        HalmosWSClient *c = registry.clients[i];
        if (c != NULL && c->is_active) {
            double diff = difftime(now, c->last_seen);
            
            printf(" [%03d] | %-3d | %-4s | %-18.0f | ONLINE\n", 
                    i, 
                    c->fd, 
                    (c->ssl ? "WSS" : "WS"), 
                    diff);
            found++;
        }
    }

    if (found == 0) {
        printf("          --- KOSONG / TIDAK ADA CLIENT ---         \n");
    }

    printf("====================================================\n\n");

    pthread_mutex_unlock(&registry.registry_lock);
}*/