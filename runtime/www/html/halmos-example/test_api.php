<?php
/**
 * Halmos Web Server - Method Testing API
 * File: test_api.php
 */

// --- 1. CORS Headers (Agar bisa ditest dari browser/frontend) ---
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Tangkap metode request
$method = $_SERVER['REQUEST_METHOD'];

// Set response sebagai JSON
header('Content-Type: application/json');

// --- 2. Logika Berdasarkan Metode ---
$response = [
    "server" => "Halmos Web Server Engine",
    "php_version" => PHP_VERSION,
    "received_method" => $method,
    "timestamp" => date('Y-m-d H:i:s')
];

switch ($method) {
    case 'GET':
        $response['message'] = "Ini adalah request GET (Read data)";
        $response['query_params'] = $_GET;
        break;

    case 'POST':
        $response['message'] = "Ini adalah request POST (Create data)";
        $response['payload'] = $_POST; // Untuk application/x-www-form-urlencoded
        // Jika kirim JSON via POST:
        $json = file_get_contents('php://input');
        $response['raw_body'] = json_decode($json, true);
        break;

    case 'PUT':
        $response['message'] = "Ini adalah request PUT (Update data)";
        // PUT data biasanya dikirim via php://input
        $putData = file_get_contents('php://input');
        $response['received_payload'] = $putData;
        
        // Coba parse jika formatnya JSON
        $decoded = json_decode($putData, true);
        $response['parsed_json'] = $decoded ?: "Not a valid JSON";
        break;

    case 'DELETE':
        $response['message'] = "Ini adalah request DELETE (Hapus data)";
        // DELETE biasanya kirim ID lewat parameter atau body
        $response['target_id'] = $_GET['id'] ?? 'Tidak ada ID yang dikirim';
        break;

    case 'OPTIONS':
        // Halmos harusnya sudah kirim ini balik via bridge
        http_response_code(204);
        exit;

    default:
        http_response_code(405);
        $response['message'] = "Metode $method tidak diizinkan";
        break;
}

// Kirim hasil ke Halmos -> Client
echo json_encode($response, JSON_PRETTY_PRINT);
?>