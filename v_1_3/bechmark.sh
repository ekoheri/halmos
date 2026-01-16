#!/bin/bash

# Konfigurasi
URL_HALMOS_PHP="http://localhost:8080/stress.php"
URL_HALMOS_HTML="http://localhost:8080/index.html"
URL_APACHE_PHP="http://localhost:80/stress.php"
URL_APACHE_HTML="http://localhost:80/index.html"

CONCURRENCIES=(10 50 100 150)
OUTPUT_FILE="hasil_mixed_workload.txt"

echo "=== PENGUJIAN MIXED WORKLOAD ===" > $OUTPUT_FILE
echo "Skenario: Mengukur latency HTML saat PHP sedang sibuk." >> $OUTPUT_FILE

run_mixed_test() {
    local label=$1
    local url_php=$2
    local url_html=$3
    local c=$4

    echo "Menguji $label (Mixed) dengan Concurrency: $c..."
    echo "------------------------------------------------" >> $OUTPUT_FILE
    echo "SERVER: $label | CONCURRENCY: $c" >> $OUTPUT_FILE
    
    # 1. Jalankan beban PHP di background (&)
    # Kita buat total request (n) banyak supaya tidak selesai duluan
    ab -n 5000 -c $c $url_php > /dev/null 2>&1 &
    PHP_PID=$!
    
    # Beri jeda 1 detik agar thread mulai terisi beban PHP
    sleep 1
    
    # 2. Ukur performa HTML saat PHP sedang berjalan
    echo "Mencatat performa HTML..." >> $OUTPUT_FILE
    ab -n 1000 -c 10 $url_html | grep -E "Requests per second|Time per request|99%" >> $OUTPUT_FILE
    
    # 3. Matikan proses ab PHP jika masih berjalan
    kill $PHP_PID > /dev/null 2>&1
    echo "" >> $OUTPUT_FILE
}

# --- TES APACHE ---
for c in "${CONCURRENCIES[@]}"; do
    sudo systemctl restart php7.4-fpm
    sleep 2
    run_mixed_test "APACHE" "$URL_APACHE_PHP" "$URL_APACHE_HTML" $c
done

# --- TES HALMOS ---
for c in "${CONCURRENCIES[@]}"; do
    sudo systemctl restart php7.4-fpm
    sleep 2
    run_mixed_test "HALMOS" "$URL_HALMOS_PHP" "$URL_HALMOS_HTML" $c
done

echo "Selesai! Hasil ada di $OUTPUT_FILE"