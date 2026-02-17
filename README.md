# Halmos Web Server Engine v0.2.x

Halmos adalah engine web server berbasis C yang dirancang untuk performa tinggi dan integrasi sistem Linux yang erat.Batasan sistem ini hanya bisa berjalan di lingkungan Sistem Operasi Linux

## 1. Instalasi Library Prasyarat
Sebelum melakukan kompilasi, pastikan sistem Anda memiliki alat pengembangan dasar:
```bash
sudo apt update
sudo apt install build-essential gcc make git libpthread-stubs0-dev libssl-dev
```
## 2. Instalasi Dependency (PHP, Rust, Python)
Halmos mendukung berbagai backend melalui FastCGI. Instal komponen berikut untuk dukungan penuh:

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
## 3. Kompilasi dan instalasi
Gunakan perintah berikut untuk mengambil kode sumber dan memasangnya ke dalam sistem:

### Clone dan kompilasi
```bash
git clone https://github.com/ekoheri/halmos.git
cd halmos
```
### Memasang ke Sistem
Perintah ini akan menyalin binary ke /usr/bin, konfigurasi ke /etc/halmos, dan mendaftarkan service ke systemd..
```bash
sudo make install
```
## 4. Cara Menjalankan
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

## 5. Fitur Baru: Dynamic Routing & TLS
Versi 0.2.2 memperkenalkan sistem manajemen yang lebih fleksibel:
 - Dynamic Routing: Halmos secara otomatis mendeteksi file .htroute di direktori root dokumen Anda. Jika file tidak ada, Halmos akan membuatnya secara otomatis.
 - TLS/SSL Support: Mendukung enkripsi HTTPS menggunakan OpenSSL.
 - Auto Reload: Server akan memantau perubahan pada konfigurasi route setiap 5 detik tanpa perlu restart manual. Tabel routing terletak di /var/www/halmos/html/.htroute

## 6. Uji Web Server
Setelah service berjalan, Anda dapat memverifikasi hasilnya dengan beberapa cara:

### Cek via Terminal
```bash
curl -l http://localhost:8080
```
### Cek via Browser
Buka browser dan akses: http://localhost:8080 atau http://ip-server-anda:8080. Pastikan file index sudah tersedia di direktori /var/www/halmos/html.

## 7. Pembersihan (Uninstall)
Untuk menghapus seluruh file build dan menghapus Halmos dari sistem secara total:
```bash
make clean
```

