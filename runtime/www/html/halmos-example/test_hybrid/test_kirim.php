<?php
require_once 'Halmos_IPC.php';

// Contoh: Kirim notifikasi ke user "Eko"
$sukses = Halmos_IPC::send("Eko", "notification", "Ada orderan baru masuk, Boss!");

if ($sukses) {
    echo "Pesan sudah terkirim ke Halmos!";
} else {
    echo "Gagal konek ke Halmos. Cek apakah Halmos jalan?";
}