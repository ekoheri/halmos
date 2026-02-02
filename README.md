# Halmos Web Server Engine v2.0.0

Halmos adalah engine web server berbasis C yang dirancang untuk performa tinggi dan integrasi sistem Linux yang erat.

## 1. Instalasi Library Prasyarat
Sebelum melakukan kompilasi, pastikan sistem Anda memiliki alat pengembangan dasar:
```bash
sudo apt update
sudo apt install build-essential gcc make git libpthread-stubs0-dev
```
## 2. Instalasi Dependency (PHP, Rust, Python)
Halmos mendukung berbagai backend melalui FastCGI. Instal komponen berikut untuk dukungan penuh:

# PHP-FPM & Spawn-FCGI
```bash
sudo apt install php-fpm spawn-fcgi
```
# Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
```
# Python & Flup (Untuk WSGI/FastCGI)
```bash
sudo apt install python3 python3-pip
pip install flup
```
## 3. Tata Cara Pull & Instalasi
Gunakan perintah berikut untuk mengambil kode sumber dan memasangnya ke dalam sistem:

# Pull dari Repositori
```bash
git clone [https://github.com/ekoheri/halmos.git](https://github.com/ekoheri/halmos.git)
cd halmos
```
# Kompilasi & Make Install
Perintah ini akan mengompilasi binary dan meletakkan file konfigurasi ke /etc/halmos serta service ke /etc/systemd/system/.
```bash
make
sudo make install
```
## 4. Menjalankan Service Halmos
Gunakan systemctl untuk mendaftarkan dan menjalankan daemon:
```bash
# Muat ulang konfigurasi systemd
sudo systemctl daemon-reload

# Aktifkan agar jalan otomatis saat boot
sudo systemctl enable halmos

# Jalankan service
sudo systemctl start halmos

# Cek status
systemctl status halmos
```
## 5. Uji Web Server
Setelah service berjalan, Anda dapat memverifikasi hasilnya dengan beberapa cara:

# Cek via Terminal
```bash
curl -l http://localhost:8080
```
# Cek via Browser
Buka browser dan akses: http://localhost:8080 atau http://ip-server-anda:8080. Pastikan file index sudah tersedia di direktori /var/www/halmos/html.
