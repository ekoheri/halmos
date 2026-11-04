<?php
// Pastikan tidak ada buffer yang menahan output
if (function_exists('apache_set_imenv')) {
    @apache_set_env('no-gzip', '1');
}
@ini_set('zlib.output_compression', '0');
@ini_set('output_buffering', 'off');
@ini_set('implicit_flush', 'true');

// Bersihkan semua level buffer jika ada
while (ob_get_level() > 0) {
    ob_end_flush();
}

// Header wajib untuk teks/plain streaming
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no'); // Mencegah proxy/Nginx buffering (jika berlapis)

echo "=== HALMOS REAL-TIME STREAMING TEST ===\n";
flush();

for ($i = 1; $i <= 5; $i++) {
    echo "[$i/5] Mendorong chunk data ke server pada " . date('H:i:s') . "\n";
    flush();
    sleep(1); // Jeda 1 detik untuk melihat efek real-time di klien
}

echo "=== STREAMING SELESAI DENGAN SUKSES ===\n";
flush();
?>