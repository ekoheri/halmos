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
 * perangkat keras secara *real-time* sebagai sumber kebenaran tunggal untuk 
 * mengatur batasan operasional internal secara dinamis.
 * 
 * Saat diinisialisasi, mesin adaptif ini mengkalibrasi diri di atas tiga pilar 
 * sumber daya utama (CPU, RAM dan File Descriptor/FD) tanpa memerlukan intervensi manual pada berkas konfigurasi:
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
 *      Angka 1024 adalah batas optimal standar Linux untuk mengambil batch event jaringan 
 *      (misal via epoll_wait) tanpa membebani memori stack CPU atau memicu latency spike.
 * 
 * 2. MANAJEMEN ANGGARAN MEMORI BERBASIS RAM (Cadangan Aman OS & Database):
 *    - Telemetri & Kebijakan Alokasi: Membaca memori sistem via `sysinfo()` dan 
 *      secara otomatis menyisihkan 25% buffer pengaman untuk Sistem Operasi serta 
 *      mesin database lokal (MySQL/PostgreSQL/Redis).
 *    - Rumus Dasar & Komputasi:
 *        * total_ram_mb      = (si.totalram * si.mem_unit) / (1024 * 1024)
 *        * reserved_ram_mb   = clamp(total_ram_mb / 4, 512, 4096)
 *        * available_for_web = total_ram_mb - reserved_ram_mb
 *    - Alokasi Proporsional Backend Berdasarkan Jumlah yang Aktif:
 *        * 3 Backend (PHP/Python/Rust): 50% / 30% / 20% dari available_for_web
 *        * 2 Backend (Misal PHP/Python): 60% / 40% dari available_for_web
 *        * 1 Backend Aktif: 100% dari available_for_web
 *    - Batas Maksimum Worker per Backend Berdasarkan RAM:
 *        * max_php_by_ram    = php_budget_ram / php_mem_budget
 *        * max_python_by_ram = python_budget_ram / python_mem_budget
 *        * max_rust_by_ram   = rust_budget_ram / rust_mem_budget
 * 
 * 3. PENYELARASAN FILE DESCRIPTOR (FD) & KAPASITAS ANTREAN:
 *    - Telemetri: Membaca batasan proses secara jujur (`RLIMIT_NOFILE` / ulimit) 
 *      menggunakan `getrlimit()` tanpa mencoba memodifikasi kernel secara paksa.
 *    - Rumus Dasar & Komputasi:
 *        * g_max_fd          = max(64, rlim_cur)
 *        * sisa_fd           = (g_max_fd > g_worker_max) ? (g_max_fd - g_worker_max) : 0
 *        * g_queue_capacity  = (sisa_fd > 0) ? (sisa_fd * 60) / 100 : 256
 *    - Pengaman (Guardrails): Kapasitas antrean tugas (*Task Queue*) dibatasi 
 *      oleh plafon internal (`MAX_QUEUE_CAPACITY: 4096`) dengan batas bawah (floor) 256:
 *        * g_queue_capacity  = clamp(g_queue_capacity, 256, MAX_QUEUE_CAPACITY)
 * 
 * 4. FCGI QUOTA MAPPING (ALOKASI KUOTA WORKER BACKEND):
 *    - php_quota           = is_php_active ? php.max_children : 0
 *    - sisa_jatah          = max(0, g_worker_max - php_quota)
 *    - Python/Rust Quota   = Didistribusikan proporsional dari sisa_jatah berdasarkan rasio RAM.
 * ========================================================================== */

#define MAX_EVENT_BATCH_SIZE 1024

#define MAX_QUEUE_CAPACITY 4096

// Fungsi tunggal untuk menghitung semua parameter adaptive saat startup
void core_adaptive_init(int print_to_terminal);
void core_adaptive_advisor(const char *filepath_arg);

#endif