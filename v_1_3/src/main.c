#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "../include/core/web_server.h"
#include "../include/core/config.h"
#include "../include/core/log.h"
#include "../include/core/queue.h"

// Inisialisasi variabel global dari web_server
Config config;
TaskQueue global_queue;

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
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);

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
    
    /*******************************************************************
     * 3. Deteksi Core & Setup Thread Pool
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
     *******************************************************************/
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) num_cores = 1;

    int dynamic_min = (int)num_cores * 2;
    int dynamic_max = (int)num_cores * 8;

    init_queue(&global_queue, dynamic_min, dynamic_max);

    /*******************************************************************
     * 4. Logging Startup
     * ANALOGI :
     * Seperti papan pengumuman:
     * "Halmos resmi buka!
     *  Core tersedia: X
     *  Pegawai: min Y – max Z"
     *
     * Berguna untuk audit dan debugging.
     *******************************************************************/
    write_log("Halmos Engine Started. Core: %ld. Dynamic Pool: %d-%d", 
              num_cores, dynamic_min, dynamic_max);

     /*******************************************************************
      * 5. Menjalankan Worker Threads
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
    for (int i = 0; i < global_queue.total_workers; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, worker_routine, &global_queue);
        pthread_detach(tid);
    }

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