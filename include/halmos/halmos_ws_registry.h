#ifndef HALMOS_WS_REGISTRY_H
#define HALMOS_WS_REGISTRY_H

#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/ssl.h>

/* --- KONFIGURASI REGISTRY --- */
#define MAX_WS_CLIENTS 1024   // Maksimal total koneksi simultan
#define HASH_SIZE 1024        // Ukuran tabel hash untuk topik
#define MAX_TOPICS_PER_USER 5 // Maksimal grup yang bisa diikuti satu user

/* * 1. STRUKTUR LOW-LEVEL (Linked List untuk Hash Table)
 * Digunakan untuk menyimpan daftar FD yang langganan topik tertentu.
 */
typedef struct ws_subscriber {
    int fd;
    struct ws_subscriber *next;
} ws_subscriber_t;

/* * 2. STRUKTUR TOPIC BUCKET
 * Merepresentasikan satu "Kamar" atau "Grup" pesan.
 */
typedef struct {
    char topic_name[128];      // Format: "app_id:topic_name"
    ws_subscriber_t *head;     // List FD yang ada di grup ini
    pthread_mutex_t topic_lock; // Lock per-topik (Granular Locking)
} ws_topic_bucket_t;

/* * 3. STRUKTUR CLIENT (Dunia Array)
 * Menyimpan metadata lengkap setiap koneksi.
 */
typedef struct {
    int fd;
    SSL *ssl;
    time_t last_seen;
    bool is_active;
    pthread_mutex_t client_lock; 
    
    // Catatan internal agar saat disconnect bisa langsung hapus di Hash Table
    char subscribed_topics[MAX_TOPICS_PER_USER][64]; 
    int topic_count;
} HalmosWSClient;

/* * 4. PUSAT KOMANDO REGISTRY (Hybrid Structure)
 */
typedef struct {
    // Jalur Administrasi (Looping linear untuk Heartbeat/Reaper)
    HalmosWSClient *clients[MAX_WS_CLIENTS];
    int current_count;
    pthread_mutex_t registry_lock; 

    // Jalur Distribusi Pesan (Akses cepat O(1) untuk PUB/SUB)
    ws_topic_bucket_t *buckets[HASH_SIZE];
    pthread_mutex_t hash_lock; 
} HalmosWSRegistry;

/* ===================================================================
 * API PUBLIK (Fungsi-fungsi yang akan dipanggil dari luar)
 * =================================================================== */

/**
 * Inisialisasi memori, mutex, dan struktur data registry.
 */
void ws_registry_init();

/**
 * Daftarkan client ke array utama setelah handshake HTTP sukses.
 */
int ws_registry_add(int fd, SSL *ssl);

/**
 * Hapus client dari array DAN bersihkan namanya dari semua bucket Hash Table.
 */
void ws_registry_remove(int fd);

/**
 * Update timestamp aktivitas terakhir (cegah ditendang Reaper).
 */
void ws_registry_update_activity(int fd);

/**
 * Loop internal untuk mengirim PING ke semua client yang aktif.
 */
void ws_registry_heartbeat();

/**
 * Loop internal untuk menutup koneksi yang sudah AFK (Timeout).
 */
void ws_registry_reaper();

/**
 * ROUTING: Daftarkan FD ke topik tertentu dalam konteks App ID.
 */
void ws_registry_add_to_topic(int fd, const char *app_id, const char *topic);

/**
 * ROUTING: Kirim pesan ke semua subscriber di dalam topik tersebut.
 */
void ws_registry_publish(const char *app_id, const char *topic, const char *message);

/**
 * BROADCAST: Kirim ke seluruh koneksi tanpa peduli topik (Sapu Jagat).
 */
void ws_registry_broadcast(const char *message);

/**
 * Cleanup total memori dan hancurkan semua mutex saat shutdown.
 */
void ws_registry_destroy();

#endif // HALMOS_WS_REGISTRY_H