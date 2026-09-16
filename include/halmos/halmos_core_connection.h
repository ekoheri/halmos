#ifndef HALMOS_CORE_CONNECTION_H
#define HALMOS_CORE_CONNECTION_H
 
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
 
// Forward declaration untuk SSL agar tidak wajib include header openssl di sini jika tidak diperlukan
typedef struct ssl_st SSL;
 
typedef enum {
    CONN_STATE_READING = 0,
    CONN_STATE_PROCESSING,
    CONN_STATE_WRITING,
    CONN_STATE_CLOSING,
    CONN_STATE_DEAD
} halmos_conn_state_t;
 
typedef struct {
    int fd;
    
    /**
     * Identifies a particular lifetime of an FD.
     * Incremented every time the FD is assigned to a new connection.
     * Worker events must carry this value to detect stale FD reuse.
     */
    _Atomic uint32_t generation;
    
    _Atomic bool active;
    _Atomic halmos_conn_state_t state;
 
    /* --- TAMBAHAN KRITIS UNTUK SYNC & I/O ISOLATION --- */
    pthread_mutex_t io_lock;  /**< Mengunci seluruh operasi I/O (SSL_read/write, HTTP/2 frame, close) */
    SSL *ssl;                 /**< Pointer SSL/TLS context per koneksi */
 
    /* --- TAMBAHAN KRITIS FOR PARTIAL WRITE / NON-BLOCKING STREAMING --- */
    uint8_t *write_buf;       /**< Pointer buffer respon yang sedang/belum selesai terkirim */
    size_t   write_len;       /**< Total ukuran payload respon (misal 1052083 byte) */
    size_t   write_offset;    /**< Jumlah byte yang sudah SUKSES dikirim via SSL_write */
    
    uint32_t epoll_events;    /**< Track masker event epoll aktif (EPOLLIN vs EPOLLOUT) */

    /* --- TAMBAHAN: STATE PROTOKOL PERSISTEN PER-KONEKSI ---
     * Dipakai untuk menyimpan state session yang harus bertahan LINTAS
     * beberapa kali dispatch (misal HTTP2Session, yang tidak boleh
     * dibuat ulang dari nol setiap worker dipanggil untuk fd yang sama).
     *
     * Sengaja pakai void* + function pointer generik, BUKAN tipe
     * HTTP2Session* langsung - supaya modul core_connection ini TIDAK
     * perlu #include header protokol spesifik (hindari circular
     * dependency: connection.h dipakai luas oleh banyak modul, sementara
     * http2_manager.h butuh connection.h juga).
     *
     * Modul yang MEMBUAT session (misal http2_manager.c) bertanggung
     * jawab men-set kedua field ini bersamaan. Modul core (connection.c,
     * event_loop.c) hanya memanggil destructor-nya secara generik saat
     * cleanup/shutdown, tanpa tahu isi struct-nya.
     */
    void *protocol_session;
    void (*protocol_session_destroy)(void *session);
} halmos_conn_t;
 
/**
 * FD lifetime payload yang dilempar oleh Event Loop ke Worker Queue
 */
typedef struct {
    int fd;
    uint32_t generation;
    uint32_t events;
} halmos_event_t;
 
// API Core Connection Metadata (Dinamis berdasarkan g_max_fd)
int core_conn_init(void);
void core_conn_destroy(void);
 
halmos_conn_t* core_conn_get(int fd);
uint32_t core_conn_activate(int fd);
void core_conn_deactivate(int fd);
bool core_conn_is_valid(int fd, uint32_t expected_generation);
 
// Helpmate Lock Operations
void core_conn_lock(halmos_conn_t *conn);
void core_conn_unlock(halmos_conn_t *conn);
 
/**
 * Generic protocol-session helpers.
 * PRASYARAT SAMA seperti ssl_get_for_fd/dst di halmos_sec_tls.c:
 * caller HARUS sudah memegang conn->io_lock (core_conn_lock) sebelum
 * memanggil ini. Tidak ada locking internal di sini - alasan sama:
 * menghindari self-deadlock karena semua titik pemanggilan yang ada
 * (dispatch di worker, cleanup di event loop) sudah berada di bawah
 * io_lock yang sama.
 */
void core_conn_set_protocol_session(halmos_conn_t *conn, void *session, void (*destroy_fn)(void *));
void core_conn_destroy_protocol_session(halmos_conn_t *conn);
void core_conn_clear_write_buf(halmos_conn_t *conn);
 
#endif // HALMOS_CORE_CONNECTION_H
