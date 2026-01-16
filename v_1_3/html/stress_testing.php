<?php
// Set waktu eksekusi agar tidak terputus untuk tugas berat
set_time_limit(300);

// 1. Algoritma Fibonacci (Recursive - CPU Stack Test)
function fibonacci($n) {
    if ($n <= 1) return $n;
    return fibonacci($n - 1) + fibonacci($n - 2);
}

// 2. Algoritma Prime Sieve (Memory & Loop Test)
function sieve($limit) {
    $primes = array_fill(0, $limit + 1, true);
    $primes[0] = $primes[1] = false;
    for ($p = 2; $p * $p <= $limit; $p++) {
        if ($primes[$p]) {
            for ($i = $p * $p; $i <= $limit; $i += $p) {
                $primes[$i] = false;
            }
        }
    }
    return count(array_filter($primes));
}

// 3. Algoritma Mandelbrot (Floating Point & Nested Loop Test)
function mandelbrot($width, $height, $max_iter) {
    $sum = 0;
    for ($y = 0; $y < $height; $y++) {
        for ($x = 0; $x < $width; $x++) {
            $z_re = 0.0;
            $z_im = 0.0;
            $c_re = ($x - $width / 1.5) * 4.0 / $width;
            $c_im = ($y - $height / 2.0) * 4.0 / $height;
            
            $iter = 0;
            while ($z_re * $z_re + $z_im * $z_im <= 4.0 && $iter < $max_iter) {
                $tmp = $z_re * $z_re - $z_im * $z_im + $c_re;
                $z_im = 2.0 * $z_re * $z_im + $c_im;
                $z_re = $tmp;
                $iter++;
            }
            $sum += $iter;
        }
    }
    return $sum;
}

// Logika Pemilihan Berdasarkan Query String
$jenis = isset($_GET['jenis']) ? $_GET['jenis'] : 'info';
$start = microtime(true);
$result_msg = "";

switch ($jenis) {
    case 'fibo':
        $n = 30;
        $res = fibonacci($n);
        $result_msg = "Fibonacci($n) = $res";
        break;
    case 'prime':
        $limit = 1000000;
        $res = sieve($limit);
        $result_msg = "Sieve Prima hingga $limit = $res ditemukan";
        break;
    case 'mandelbrot':
        $res = mandelbrot(800, 600, 1000);
        $result_msg = "Mandelbrot Checksum = $res";
        break;
    default:
        echo "<h1>Halmos Stress Test (PHP)</h1>";
        echo "Gunakan parameter: ?jenis=fibo, ?jenis=prime, atau ?jenis=mandelbrot";
        exit;
}

$end = microtime(true);
$duration = round($end - $start, 6);

echo "<h1>PHP Stress Test: " . ucfirst($jenis) . "</h1>";
echo "<p><strong>Hasil:</strong> $result_msg</p>";
echo "<p><strong>Waktu Eksekusi:</strong> $duration detik</p>";
?>