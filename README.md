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
    - Menghubungkan permintaan dinamis ke backend aplikasi (seperti PHP-FPM) melalui connection pool asinkronus.
    - Dilengkapi pengaman timeout (30 detik) untuk membersihkan soket macet secara bersih (stalled socket cleanup).

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

Lakukan konfigurasi sistem, sebelum web server dijalankan. Sesuaikan dengan environment system anda. 

Konfigurasi terletak di folder 
```bash
/etc/halmos/halmos.conf
```

Buka file konfigurasi dengan:
```bash
nano /etc/halmos/halmos.conf
```

⚠️ PENTING — Periksa Konfigurasi PHP-FPM

Perhatikan konfigurasi berikut:
```bash
php_fpm_config_path = /etc/php/8.2/fpm/pool.d/www.conf
```
Path tersebut tidak selalu sama pada setiap sistem. Angka 8.2 pada contoh di atas hanya menunjukkan versi PHP-FPM yang digunakan pada environment pengembang Halmos.

Jika sistem Anda menggunakan versi PHP-FPM yang berbeda, sesuaikan php_fpm_config_path dengan versi PHP-FPM yang terpasang pada sistem Anda.

Untuk mengetahui versi PHP yang terpasang, jalankan:
```bash
php -v
```
Anda juga dapat melihat versi PHP yang tersedia pada sistem dengan:
```bash
ls /etc/php/
```
Misalnya, jika sistem Anda menggunakan PHP 8.3, ubah menjadi:
```bash
php_fpm_config_path = /etc/php/8.3/fpm/pool.d/www.conf
```

Pastikan file konfigurasi PHP-FPM tersebut benar-benar tersedia:
```bash
ls -l /etc/php/8.3/fpm/pool.d/www.conf
```
Jika php_fpm_config_path tidak sesuai dengan sistem Anda, Halmos tetap dapat mengalami masalah ketika membaca konfigurasi PHP-FPM. Konfigurasi ini digunakan oleh Adaptive Engine Halmos untuk membaca parameter PHP-FPM, termasuk max_children, sehingga path yang benar diperlukan agar mekanisme Adaptive dapat bekerja sebagaimana mestinya.

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
[12:09:31.539] [INFO] [CORE] Hardware-Aware Init -> Cores: 8 | RAM: 7836 MB | Max FD: 1024
[12:09:31.539] [INFO] [CORE] Workers (Min/Recommended Ceiling): 32/512 | Event Batch: 512 | Queue Capacity: 307
[12:09:31.539] [INFO] [FCGI] Quotas -> PHP: 5 | Rust: 202 | Python: 305 | Total Pool: 512
[12:09:31.539] [INFO] [WARN] System ulimit (1024) is lower than recommended headroom (1319)
[12:09:31.539] [INFO] [ADVICE] Action: Run 'ulimit -n 1319' for optimal FD headroom
[12:09:31.539] [INFO] [ADVICE] PHP-FPM max_children (5) is conservative for detected hardware
[12:09:31.539] [INFO] [ADVICE] Action: Consider scaling pool in '/etc/php/8.2/fpm/pool.d/www.conf' up to max_children = 256 based on PHP workload
[12:09:31.539] [INFO] [ADVICE] Supporting Config Tip -> Adjust pm.start_servers = 64, min_spare = 64, max_spare = 128 accordingly
```

### 2. Penjelasan Detail Angka Berdasarkan Kondisi Hardware

- Cores: 8 | RAM: 7836 MB | Max FD: 1024

    - Artinya bagi Admin: Halmos membaca realitas perangkat keras sistem operasi Anda secara langsung saat booting. Batas maksimal koneksi bersamaan (File Descriptor atau jatah soket jaringan aktif) yang diizinkan oleh sistem Linux Anda saat ini adalah 1024 koneksi.

- Workers (Min/Recommended Ceiling): 32/512

    - Artinya bagi Admin: Berdasarkan jumlah inti (core) prosesor (CPU), Halmos merekomendasikan batas plafon (ceiling) kapasitas pelayan aktif sebanyak 512 worker (dengan minimal 32 worker saat sistem sepi). Angka ini adalah baseline adaptif, bukan batas mati (hard limit)..

- Event Batch: 512

    - Artinya bagi Admin: Jumlah paket koneksi masuk yang ditarik dan diproses oleh CPU secara bersamaan dalam satu siklus putaran sistem (menggunakan teknologi asinkronus Linux epoll).

- Queue Capacity: 307

    - Artinya bagi Admin: Ruang tunggu darurat (buffer antrean) yang dihitung secara proporsional dari sisa File Descriptor aktual (Max FD dikurangi alokasi Worker). Jika 512 pelayan sedang sibuk, server menampung hingga 307 antrean pengunjung berikutnya di RAM agar tidak langsung mendapat error Connection Refused.

- Quotas -> PHP: 5 | Rust: 202 | Python: 305 | Total Pool: 512

    - Artinya bagi Admin: Pembagian jatah pelayan (backend bridge) untuk masing-masing bahasa. Halmos tetap menghormati konfigurasi murni administrator (max_children = 5 untuk PHP-FPM), sementara sisa kapasitas pool dibagi secara proporsional untuk backend Rust dan Python.

### 3. Membaca Peringatan & Tindakan (Action) yang Harus Diambil

### A. Peringatan Batasan Sistem ([WARN] & [ADVICE] Ulimit):

- Pesan: System ulimit (1024) is lower than recommended headroom (1319)

- Artinya: Batas sistem operasi Linux Anda (1024) lebih kecil dari kalkulasi ideal yang dibutuhkan server (512 worker + 307 queue + 500 buffer keamanan = 1319). Jika trafik memuncak, koneksi baru bisa tertolak oleh OS.

- Solusi Admin: Jalankan perintah terminal dibawah ini, sesuai saran log. Lalu restart ulang web server Halmos.
```bash
ulimit -n 1319
```

### B. Saran Pengaturan Backend ([ADVICE] PHP-FPM):

- Pesan: PHP-FPM max_children (5) is conservative for detected hardware.

- Artinya: Konfigurasi PHP-FPM Anda saat ini tergolong sangat konservatif (5 proses) dibandingkan kapasitas perangkat keras 8 core yang terdeteksi. Halmos tidak memaksakan perubahan secara otomatis, melainkan memberikan pengingat berbasis advisory.

- Solusi Admin: Buka file konfigurasi PHP-FPM Anda sesuai jalur yang tertera di log (/etc/php/8.2/fpm/pool.d/www.conf), lalu sesuaikan parameter prosesnya secara holistik agar manajemen proses tetap stabil. Tetapi angka konfigurasi dibawah ini, hanya contoh ya, untuk angka persisnya silahkan disesuaikan dengan kondisi hardware dan kebutuhan anda. 
```bash
pm.max_children = 256
pm.start_servers = 64
pm.min_spare_servers = 64
pm.max_spare_servers = 128
```