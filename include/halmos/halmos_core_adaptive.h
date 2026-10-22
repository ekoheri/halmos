#ifndef HALMOS_CORE_ADAPTIVE_H
#define HALMOS_CORE_ADAPTIVE_H

/* ==========================================================================
 * HALMOS ADAPTIVE CAPACITY & HARDWARE-AWARE INITIALIZATION ENGINE
 * --------------------------------------------------------------------------
 * DESAIN ARSITEKTUR & EPISTEMOLOGI:
 * 
 * Halmos menolak paradigma konfigurasi statis tradisional di mana administrator 
 * dipaksa menebak-nebak parameter operasional optimal secara manual. Sebaliknya, 
 * web server menganut prinsip "kesadaran empiris mandiri" — mempercayakan telemetri 
 * perangkat keras secara real-time sebagai sumber kebenaran tunggal untuk 
 * mengatur batasan operasional internal secara dinamis.
 * 
 * Saat diinisialisasi, mesin adaptif ini mengkalibrasi dirinya di atas tiga pilar 
 * sumber daya utama (CPU, RAM dan File Descriptor/FD), tanpa memerlukan intervensi 
 * manual pada berkas konfigurasi, serta membaginya secara tegas ke dalam domain:
 * 
 * 1. HEURISTIK KONKURENSI BERBASIS CPU (Penskalaan Worker & Event Batch):
 *    - Alasan: Event loop non-blocking I/O mampu menangani banyak deskriptor 
 *      secara serentak per inti (core) CPU. Heuristik ini menjamin saturasi CPU yang tinggi 
 *      tanpa memicu overhead akibat pergantian tugas (context switching) berlebih.
 *    - Rumus Dasar & Komputasi:
 *        * cpu_based_max     = num_cores * 64
 *        * ram_total_max     = max_php_by_ram + max_python_by_ram + max_rust_by_ram
 *        * recommended_val   = min(cpu_based_max, ram_total_max)
 *    - Pengaman (Guardrails) & Batasan Worker:
 *        * g_worker_max      = clamp(recommended_val, 32, 1024)
 *        * g_worker_min      = min(num_cores * 4, g_worker_max)
 *    - Kaitannya dengan MAX_EVENT_BATCH_SIZE: 
 *      Batasan pemrosesan event per siklus (`MAX_EVENT_BATCH_SIZE: 1024`) diselaraskan 
 *      secara langsung dengan batas maksimal worker ini (`g_event_batch_size = min(g_worker_max, 1024)`). 
 * 
 * 2. MANAJEMEN ANGGARAN MEMORI BERBASIS RAM (Cadangan Aman OS & Database):
 *    - Telemetri & Kebijakan Alokasi: Membaca memori sistem via `sysinfo()` dan 
 *      secara otomatis menyisihkan 25% buffer pengaman untuk Sistem Operasi serta 
 *      mesin database lokal (MySQL/PostgreSQL/Redis).
 *    - Rumus Dasar & Komputasi:
 *        * total_ram_mb      = (si.totalram * si.mem_unit) / (1024 * 1024)
 *        * reserved_ram_mb   = clamp(total_ram_mb / 4, 512, 4096)
 *        * available_for_web = total_ram_mb - reserved_ram_mb
 *    - Alokasi Proporsional Backend & Upstream Buffer (`g_fcgi_upstream_slots` & `g_fcgi_queue_capacity`):
 *        * Menghasilkan kuota slot paralel aman untuk PHP, Rust, dan Python berdasarkan 
 *          anggaran RAM bersih agar proses anak FPM tidak memicu *OOM Killer*.
 *        * `g_fcgi_queue_capacity`: Buffer antrean tunggu yang menampung request HTTP 
 *          tatkala seluruh slot upstream/FPM sibuk, mencegah penolakan koneksi mentah (ECONNREFUSED).
 * 
 * 3. PENYELARASAN FILE DESCRIPTOR (FD) & ANTREAN FRONTEND (`g_core_max_fd` & `g_core_queue_capacity`):
 *    - Telemetri: Membaca batasan proses secara jujur (`RLIMIT_NOFILE` / ulimit) 
 *      menggunakan `getrlimit()` tanpa mencoba memodifikasi kernel secara paksa.
 *    - Rumus Dasar & Komputasi Core FD:
 *        * g_core_max_fd     = clamp(rlim_cur, 64, UINT32_MAX)  // (Ditangani jika unlimited)
 *    - Integrasi Antar Pilar (CPU, RAM, & FD) pada Queue Frontend:
 *        * sisa_fd           = (g_core_max_fd > (uint32_t)g_worker_max) ? (g_core_max_fd - (uint32_t)g_worker_max) : 0
 *        * g_core_queue_capacity = clamp((sisa_fd * 60) / 100, 256, MAX_QUEUE_CAPACITY)
 *    - Epistemologi Antrean: Meskipun dihitung dari sisa FD, kapasitas antrean ini 
 *      secara dinamis dikoreksi oleh kapasitas CPU (`g_worker_max` sebagai pengurang) 
 *      dan divalidasi selaras dengan batas aman RAM backend (`g_fcgi_upstream_slots`) 
 *      untuk menampung gelombang request masuk secara aman.
 * 
 * 4. FCGI QUOTA MAPPING (ALOKASI KUOTA WORKER BACKEND):
 *    - php_quota           = is_php_active ? php.max_children : 0
 *    - sisa_jatah          = max(0, g_worker_max - php_quota)
 *    - Python/Rust Quota   = Didistribusikan proporsional dari sisa_jatah berdasarkan rasio RAM.
 *    - g_fcgi_upstream_slots = Total keseluruhan slot upstream yang diizinkan aktif.
 * 
 * --------------------------------------------------------------------------
 * REPRESENTASI HIERARKI PILAR & ALUR SUMBER DAYA (TREE VIEW):
 * --------------------------------------------------------------------------
 * [ PILAR FISIK / HARD CONSTRAINTS ]
 *  ├── 1. CPU (Core Count)
 *  │    └── Menentukan: WORKER THREAD POOL
 *  │         ├── g_worker_min        (Baseline thread siaga, misal: Core Count * 4)
 *  │         └── g_worker_max        (Plafon pekerja aktif, misal: Core Count * 64, maks 1024)
 *  │
 *  ├── 2. RAM (Memory Budget & Available RAM)
 *  │    └── Menentukan: BACKEND / FASTCGI UPSTREAM SLOTS
 *  │         ├── g_fcgi_upstream_slots (Total slot aman untuk PHP + Rust + Python)
 *  │         │    ├── php_quota        (Dibatasi max_children * RAM budget PHP per process)
 *  │         │    ├── rust_quota       (Dibatasi RAM budget Rust per process)
 *  │         │    └── python_quota     (Dibatasi RAM budget Python per process)
 *  │         └── g_fcgi_queue_capacity (Buffer antrean tunggu saat slot backend FPM penuh)
 *  │              ├── Formula        : Dihitung proporsional dari sisa kapasitas worker/slot aktif
 *  │              └── Penjelasan     : Menampung request HTTP yang sudah lolos dari frontend 
 *  │                                   tetapi harus mengantre karena seluruh proses anak FPM (PHP/Rust/Python) 
 *  │                                   sedang sibuk melayani request lain, mencegah server menolak koneksi secara mentah (ECONNREFUSED).
 *  │
 *  └── 3. FILE DESCRIPTOR / FD (ulimit -n)
 *       └── Menentukan: CORE / FRONTEND NETWORK CAPACITY
 *            ├── g_core_max_fd       (Pintu gerbang epoll klien, hasil olahan ulimit sistem)
 *            │    ├── Sumber         : Dibaca langsung dari sistem via getrlimit(RLIMIT_NOFILE)
 *            │    └── Penjelasan     : Bukan sekadar salinan mentah ulimit, melainkan telah divalidasi:
 *            │                         jika 'unlimited' dikunci ke plafon aman (misal 65536), 
 *            │                         dan jika terlalu kecil dinaikkan ke batas minimal aman (minimal 64).
 *            └── g_core_queue_capacity (Buffer antrean HTTP request gelombang masuk)
 *                 ├── Sumber Bahan Baku (FD)   : Berasal dari g_core_max_fd (kapasitas total socket ulimit)
 *                 ├── Faktor Koreksi (CPU)     : Dikurangi oleh g_worker_max (kapasitas pekerja aktif saat itu)
 *                 ├── Pagar Pengaman (RAM)     : Dibatasi secara sistemik agar tidak membanjiri g_fcgi_upstream_slots
 *                 ├── Formula Penyelaras       : Clamp( (g_core_max_fd - g_worker_max) * 60%, 256, MAX_QUEUE_CAPACITY )
 *                 └── Penjelasan Integrasi     : Meskipun dihitung dari sisa FD, angka ini *secara tidak langsung ditentukan oleh CPU dan RAM*. 
 *                                                Kapasitas CPU (`g_worker_max`) menentukan seberapa banyak slot yang sedang dikerjakan, 
 *                                                sementara kapasitas RAM (`g_fcgi_upstream_slots`) menentukan batas akhir seberapa jauh 
 *                                                antrean ini boleh meloloskan request ke backend tanpa memicu kolaps memori.
 * ========================================================================== */

#define MAX_EVENT_BATCH_SIZE 1024

#define MAX_QUEUE_CAPACITY 4096

// Fungsi tunggal untuk menghitung semua parameter adaptive saat startup
void core_adaptive_init(int print_to_terminal);
void core_adaptive_advisor(const char *filepath_arg);

#endif