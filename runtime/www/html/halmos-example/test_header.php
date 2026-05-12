<?php
/**
 * Simple CORS Handler for Halmos Backend
 */

// 1. Tentukan domain yang diizinkan (Origin)
// Gunakan '*' untuk mengizinkan semua, atau spesifik domain tertentu
header("Access-Control-Allow-Origin: *");

// 2. Tentukan metode HTTP yang diizinkan
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

// 3. Tentukan header kustom yang diizinkan dikirim oleh client
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// 4. Durasi cache untuk hasil pre-flight request (dalam detik)
header("Access-Control-Max-Age: 86400");

/**
 * 5. HANDLING OPTIONS REQUEST (Pre-flight)
 * Browser modern akan mengirimkan metode OPTIONS sebelum POST/PUT 
 * untuk mengecek izin keamanan.
 */
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    // Jika hanya OPTIONS, kita hentikan script di sini dengan status 200/204
    http_response_code(204);
    exit;
}

// --- LOGIKA BACKEND KAMU DI SINI ---

header('Content-Type: application/json');

$response = [
    "status" => "success",
    "message" => "CORS Berhasil di Halmos!",
    "data" => [
        "user" => "Eko Heri",
        "role" => "Software Developer"
    ]
];

echo json_encode($response);
?>