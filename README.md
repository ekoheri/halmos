# Halmos Web Server: Architecture & System Documentation
- Version: 1.0.0-RC (Release Candidate Phase)
- Core Language: C (Event-driven, Multi-threaded)
- Author: Eko Heri Susanto (Informatika, ITN-Malang)

## 1. Overview & Core Philosophy
Halmos adalah event-driven high-performance custome web server yang dirancang menggunakan bahasa C. Server ini berfokus pada efisiensi eksekusi I/O-bound dan CPU-bound campuran (mixed workload), memanfaatkan arsitektur asinkronus berbasis epoll, pengelolaan memori yang ketat, serta mekanisme pengaman mandiri terhadap kegagalan komponen eksternal (backend upstream).Batasan sistem ini hanya bisa berjalan di lingkungan Sistem Operasi Linux

## 2. Peta Arsitektur 5 Lapisan (5-Layer Stack)

Arsitektur Halmos dibagi secara ketat menjadi lima lapisan fungsional untuk memisahkan tanggung jawab (separation of concerns):

### Transport Layer (TCP / Socket Management):

Mengelola network socket mentah, non-blocking I/O, dan pengikatan port jaringan.

### TLS & Security Layer (Encryption & Policy Enforcement):

Menegakkan kebijakan keamanan wajib (Strict HTTPS-only policy), menolak koneksi mentah atau tidak sah dengan respons 400 Bad Request.

### Core Engine Layer (Event-Driven & Thread Pool):

- Jantung sistem berbasis epoll untuk event multiplexing.

- Menggunakan Adaptive Thread Pool dinamis (g_worker_min hingga g_worker_max) yang melakukan upscaling dan downscaling otomatis berdasarkan beban antrean tugas (Task Queue).

### Protocol Layer (HTTP/1.1, HTTP/2 & WebSocket):

- Menangani parsing permintaan/tanggapan standar, manajemen stream framing, serta terowongan komunikasi real-time WebSocket (H1/H2).

- FastCGI & Application Integration Layer:

-- Menghubungkan permintaan dinamis ke backend aplikasi (seperti PHP-FPM) melalui connection pool asinkronus.

-- Dilengkapi pengaman timeout (30 detik) untuk membersihkan soket macet secara bersih (stalled socket cleanup).

## 3. Fitur : Dynamic Routing, TLS/SSL,HTTP/1.1, HTTP2, Websocket, Multiple Backend
Versi 0.2.8 memperkenalkan sistem manajemen yang lebih fleksibel:
 - Dynamic Routing: Mendukung resolusi jalur fleksibel menggunakan konfigurasi eksternal /var/www/html/.htroute, memungkinkan pemetaan URL dinamis secara instan tanpa perlu kompilasi ulang atau restart server.
 - TLS/SSL Support: Mendukung enkripsi HTTPS menggunakan OpenSSL.
 - Websocket : Mendukung komunikasi full-duplex real-time berbasis RFC 6455 dengan manajemen registry FD yang efisien, fitur pub/sub terintegrasi, dan performa tinggi melalui arsitektur non-blocking epoll.
 - HTTP/1.1 & HTTP/2 : Web server ini mendukung protokol HTTP/1.1 dan HTTP/2. Jika TLS/SSL diaktifkan, maka otomatis akan menjalankan protokol HTTP/2, sesuai dengan standard request dari browser. Jika TLS/SSL di-non aktifkan, maka akan menjalankan protokol HTTP/1.1   
- Multiple Backend : Web server ini mendukung berbagai backend melalui FastCGI, dalam satu ekosistem (PHP, Python, Rust). Jadi developer backend dapat menjalankan ketiga bahasa pemrograman tersebut dalam satu lingkungan. 

## 4. Instalasi Library Prasyarat
Sebelum melakukan kompilasi, pastikan sistem Anda memiliki alat pengembangan dasar:
```bash
sudo apt update
sudo apt install build-essential gcc make git libpthread-stubs0-dev libssl-dev libjson-c-dev
```
## 5. Instalasi Dependency (PHP, Rust, Python)
Halmos mendukung berbagai backend melalui FastCGI. Install komponen berikut untuk dukungan penuh:

### PHP-FPM & Spawn-FCGI
```bash
sudo apt install php-fpm spawn-fcgi
```
### Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
```
### Python & Flup (Untuk WSGI/FastCGI)
```bash
sudo apt install python3 python3-pip
pip install flup
```
## 6. Kompilasi dan instalasi
Gunakan perintah berikut untuk mengambil kode sumber dan memasangnya ke dalam sistem:

### Clone dan kompilasi
```bash
git clone https://github.com/ekoheri/halmos.git
cd halmos
```
### Memasang ke Sistem
Perintah ini akan menyalin binary ke /usr/bin, konfigurasi ke /etc/halmos, dan mendaftarkan service ke systemd.
```bash
make
sudo make install
```
### Konfigurasi Sistem

Lakukan konfigurasi sistem, sebelum web server dijalankan. Sesuaikan dengan environment system anda. Konfigurasi terletak di folder /etc/halmos/halmos.conf, dan ikuti petunjuk yang ada.
```bash
nano /etc/halmos/halmos.conf
```
Simpan perubahan konfigurasinya, dan sistem siap dijalankan.

## 7. Cara Menjalankan
Tersedia dua mode utama untuk menjalankan Halmos:

### A. Mode Produksi (Background)
Jalankan Halmos sebagai daemon systemd agar tetap berjalan di latar belakang:
```bash
make run
```
### B. Mode Debug (Foreground)
Gunakan mode ini saat pengembangan untuk melihat log secara real-time di terminal:
```bash
make debug
```
Catatan: make debug akan mengecek konflik port dengan service background secara otomatis.

## 8. Uji Web Server
Setelah service berjalan, Anda dapat memverifikasi hasilnya dengan beberapa cara:

### Cek via Terminal
```bash
curl -k -i https://localhost:8080
```
### Cek via Browser
Buka browser dan akses: https://localhost:8080 atau https://ip-server-anda:8080. 

Pastikan file index sudah tersedia di direktori /var/www/html, dan pastikan port sesuai dengan konfigurasi port anda.

### Uji Script PHP

Buka browser dan akses:
```bash
https://localhost:8080/halmos-example/test_login.php

https://localhost:8080/halmos-example/test_upload.php

https://localhost:8080/halmos-example/test_cookie.php
```

## 9. Pembersihan (Uninstall)
Untuk menghapus seluruh file build dan menghapus Halmos dari sistem secara total:
```bash
sudo make clean
```

## 10. Panduan Administrator: Membaca Log Sistem Halmos (/var/log/halmos/yyyy-mm-dd_system.log)

Halmos dirancang dengan sistem cerdas yang otomatis mendengarkan spesifikasi perangkat keras (hardware) server Anda setiap kali dinyalakan. Log ini berfungsi sebagai laporan kesehatan server dan panduan penyesuaian performa (tuning).. File log ini akan tercetak 1 (satu) file pada setiap harinya, dengan format penulisan tahun-bulan-tanggal_system.log.

### 1. Contoh Baris Log Startup & Artinya

```bash
[11:48:58.934] [INFO] [CORE] Calculated MAX_FD capacity: 1024
[11:48:58.935] [INFO] [CORE] Adaptive engine initialized (Ceiling: 1024 Workers)
[11:48:58.935] [INFO] [CORE] Workers (Min/Max): 32/512 | Event Batch: 512 | Queue Capacity: 2000
[11:48:58.935] [INFO] [FCGI] Quotas -> PHP: 5 | Rust: 202 | Python: 305 | Total Pool: 512
[11:48:58.935] [INFO] [WARN] System ulimit (1024) is lower than recommended headroom (3512)
[11:48:58.935] [INFO] [ADVICE] Action: Run 'ulimit -n 3512' for optimal FD headroom
[11:48:58.935] [INFO] [ADVICE] PHP-FPM max_children (5) is under-utilized for this hardware
[11:48:58.935] [INFO] [ADVICE] Action: Consider increasing PHP-FPM max_children up to 256
```

### 2. Penjelasan Detail Angka Berdasarkan Kondisi Hardware

- Calculated MAX_FD capacity: 1024

-- Artinya bagi Admin: Server mendeteksi batas maksimal koneksi bersamaan (File Descriptor atau jatah soket jaringan aktif) yang diizinkan oleh sistem operasi Linux Anda saat ini adalah 1024 koneksi.

- Workers (Min/Max): 32/512

-- Artinya bagi Admin: Berdasarkan jumlah inti prosesor (CPU) dan kapasitas RAM di server ini, Halmos otomatis membatasi jumlah pelayan aktif (Workers). Server akan menyiapkan minimal 32 pelayan saat sepi, dan bisa melarikan diri hingga maksimal 512 pelayan saat lalu lintas pengunjung sedang padat.

- Event Batch: 512

-- Artinya bagi Admin: Jumlah paket koneksi masuk yang ditarik dan diproses oleh CPU secara bersamaan dalam satu siklus putaran sistem (menggunakan teknologi asinkronus Linux epoll).

- Queue Capacity: 2000

-- Artinya bagi Admin: Ruang tunggu darurat (buffer antrean). Jika 512 pelayan sedang sibuk seratus persen, server akan menampung hingga 2,000 antrean pengunjung berikutnya di ruang tunggu RAM agar tidak langsung mendapat error Connection Refused.

- Quotas -> PHP: 5 | Rust: 202 | Python: 305 | Total Pool: 512

-- Artinya bagi Admin: Pembagian jatah pelayan (backend bridge) untuk masing-masing bahasa pemrograman berdasarkan porsi kinerjanya. PHP dijatah 5 proses (sesuai setelan PHP-FPM), sementara sisanya dibagi proporsional untuk backend Rust dan Python.

### 3. Membaca Peringatan & Tindakan (Action) yang Harus Diambil

### A. Peringatan Batasan Sistem ([WARN] & [ADVICE] Ulimit):

- Pesan: System ulimit (1024) is lower than recommended headroom (3512)

- Artinya: Skenario bahaya penolakan koneksi. Server Anda punya kapasitas hardware yang kuat, tapi sistem operasi Linux Anda masih membatasi akses file/koneksi jaringan di angka 1024. Jika pengunjung tembus angka tersebut, website bisa gagal diakses.

- Solusi Admin: Jalankan perintah terminal sesuai saran log sebelum menjalankan ulang server:
```bash
ulimit -n 3512
```

### B. Saran Pengaturan Backend ([ADVICE] PHP-FPM):

- Pesan: PHP-FPM max_children (5) is under-utilized

- Artinya: Hardware Anda mubazir. Server mendeteksi spesifikasi CPU dan RAM Anda sanggup melayani ratusan proses sekaligus, tetapi konfigurasi bawaan PHP-FPM Anda hanya mengizinkan 5 proses (max_children = 5). Akibatnya, website terasa lambat saat diakses banyak orang karena antre di PHP, padahal RAM dan CPU masih santai.

- Solusi Admin: Buka file konfigurasi PHP-FPM Anda (bisanya di folder /etc/php/<versi-PHP FPM>/fpm/pool.d/www.conf), lalu naikkan nilai pm.max_children mendekati angka yang disarankan log (misal ke 256) agar potensi hardware terpakai secara optimal.