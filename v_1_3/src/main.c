#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

#include "web_server.h"
#include "rate_limit.h"
#include "config.h"
#include "log.h"
#include "queue.h"

// Inisialisasi variabel global dari web_server
Config config;
TaskQueue global_queue;

// --- PROTOTYPE FUNGSI INTERNAL ---
void setup_signals();
void set_daemon();
void init_dynamic_worker_pool();
void* janitor_thread(void* arg);
void init_background_services();


/***********************************************************************
 * ANALOGI BESAR PROGRAM INI :
 *
 * File main.c adalah seperti DIREKTUR UTAMA gedung Halmos.
 * Tugasnya bukan melayani tamu langsung,
 * tapi MENYIAPKAN SELURUH INFRASTRUKTUR :
 *
 * 1. Menentukan aturan darurat (signal)
 * 2. Membaca buku SOP kantor (config)
 * 3. Membangun tim pegawai (thread pool)
 * 4. Membuka pintu gedung (bind & listen)
 * 5. Menjalankan operasional harian (event loop)
 *
 * Setelah semua siap,
 * direktur hanya mengawasi jalannya sistem.
 ***********************************************************************/
int main() {
    //1. setup signals, keterangan dibawah ya
    setup_signals();

    /*******************************************************************
     * 2. Load Config
     * ANALOGI :
     * Direktur membuka BUKU SOP HALMOS :
     * /etc/halmos/halmos.conf
     *
     * Dari sini server tahu:
     * - port berapa dipakai
     * - lokasi document root
     * - ukuran buffer
     * - alamat PHP & Rust backend
     *
     * Tanpa ini, kantor tidak tahu cara bekerja.
     *******************************************************************/
    load_config("/etc/halmos/halmos.conf");
    
    // 3. ini kalau pake SystemCTL jadi nggak guna. Maka di remark saja
    // set_daemon();

    
    init_dynamic_worker_pool();

    // 5. Jalankan Background Services (Janitor)
    // Sekarang aman membuat thread karena proses daemon sudah stabil
    init_background_services();

    /*******************************************************************
     * 6. Bind & Listen
     * ANALOGI :
     * Ini momen MEMBUKA PINTU GEDUNG :
     *
     * start_server() =
     * → pasang papan alamat,
     * → buka loket di port tertentu,
     * → siap menerima tamu dari internet.
     *******************************************************************/
    start_server();

    /*******************************************************************
     * 7. Event Loop
     * ANALOGI :
     * run_server() adalah OPERASIONAL HARIAN :
     *
     * - resepsionis menerima tamu (accept socket)
     * - tamu dimasukkan ke antrean tugas
     * - pegawai koki mengambil dan melayani
     *
     * Loop ini berjalan terus
     * sampai ada perintah tutup dari sinyal/komputer dimatikan
     *******************************************************************/
    run_server();

    return 0;
}

// --- IMPLEMENTASI FUNGSI PEMISAH ---

/*******************************************************************
 * 1. Pengaturan Signal
 * ANALOGI :
 * Ini seperti memasang ATURAN KESELAMATAN GEDUNG.
 *
 * - SIGPIPE diabaikan → kalau klien kabur tiba-tiba,
 *   server tidak ikut pingsan.
 *
 * - SIGTERM & SIGINT → tombol darurat:
 *   kalau admin tekan Ctrl+C atau kirim stop,
 *   fungsi stop_server akan dipanggil
 *   untuk mematikan layanan secara sopan.
 *******************************************************************/
void setup_signals() {
    signal(SIGPIPE, SIG_IGN);  // Abaikan koneksi putus tiba-tiba
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);
}

void* janitor_thread(void* arg) {
    while(1) {
        sleep(600); // Tidur 10 menit
        clean_old_rate_limits();
    }
    return NULL;
}

/*******************************************************************
 * Deteksi Core & Setup Thread Pool
 * ANALOGI :
 * Direktur menghitung:
 * "Gedung saya punya berapa ruang kerja (CPU core)?"
 *
 * Lalu menentukan jumlah pegawai:
 * - minimal = 2 pegawai (worker thread) per core. 
 *   Jika jumlah core 4 (Core i5) maka pegawai 4 x 2 = 8
 * - maksimal = 8 pegawai per core
 *
 * init_queue → seperti membangun RUANG DISPATCHER
 * tempat antrean tugas dan daftar pegawai aktif.
 * 
 * Menjalankan Worker Threads
    * ANALOGI :
    * Direktur merekrut pegawai (Worker Threads) satu per satu.
    *
    * Setiap pthread_create =
    * → satu pegawai koki yang siap:
    *    - mengambil tugas dari antrean
    *    - memanggil parser
    *    - mengirim response
    *
    * pthread_detach →
    * → pegawai mandiri, tidak perlu diawasi manual.
*******************************************************************/
void init_dynamic_worker_pool() {
    // Hitung Core CPU secara dinamis
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    // Kalkulasi beban: 2 worker per core (min) - 8 worker per core (max)
    int dynamic_min = (int)num_cores * 2;
    int dynamic_max = (int)num_cores * 8;

    // Inisialisasi antrean tugas
    init_queue(&global_queue, dynamic_min, dynamic_max);

    write_log("Halmos Engine: Adaptive CPU Scaling active.");
    write_log("Cores Detected: %ld. Initializing Pool: %d to %d workers.", 
              num_cores, dynamic_min, dynamic_max);

    for (int i = 0; i < global_queue.total_workers; i++) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, worker_routine, &global_queue) == 0) {
            pthread_detach(tid);
        }
    }
}

void init_background_services() {
    pthread_t log_tid, janitor_tid;
    // Jalankan Logger Thread
    if (pthread_create(&log_tid, NULL, log_thread_routine, NULL) == 0) {
        pthread_detach(log_tid);
    }

    // Membuat thread janitor untuk membersihkan rate limit setiap 10 menit
    if (pthread_create(&janitor_tid, NULL, janitor_thread, NULL) == 0) {
        pthread_detach(janitor_tid); // Agar thread berjalan mandiri
        write_log("Background Service: Janitor thread started.");
    }
}
