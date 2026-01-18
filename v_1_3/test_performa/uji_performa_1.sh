#!/bin/bash

# Konfigurasi
URL_APACHE="http://127.0.0.1:80/index.html"
URL_NGINX="http://127.0.0.1:81/index.html"
URL_HALMOS="http://127.0.0.1:8080/index.html"

# Skenario Concurrency: Ringan (10), Menengah (100), Berat (500), Ekstrim (1000)
CONCURRENCY=(10 100 500 1000) 
OUTPUT_FILE="BATTLE_ROYALE_$(date +%Y%m%d_%H%M).txt"

# Pastikan bc terinstall
if ! command -v bc &> /dev/null; then
    echo "Error: 'bc' tidak ditemukan. Install dulu: sudo apt install bc"
    exit 1
fi

echo "=================================================" > $OUTPUT_FILE
echo "   BATTLE ROYALE: APACHE VS NGINX VS HALMOS" >> $OUTPUT_FILE
echo "   Tanggal: $(date)" >> $OUTPUT_FILE
echo "   Skenario: Bertahap (Variable Requests)" >> $OUTPUT_FILE
echo "=================================================" >> $OUTPUT_FILE

get_ram() {
    local proc_match=$1
    # Mengambil RSS (Physical RAM)
    local ram_kb=$(ps aux | grep "$proc_match" | grep -v grep | awk '{sum+=$6} END {print sum}')
    if [ -z "$ram_kb" ] || [ "$ram_kb" -eq 0 ]; then
        echo "0.00"
    else
        echo "$(echo "scale=2; $ram_kb / 1024" | bc)"
    fi
}

run_bench() {
    local name=$1
    local url=$2
    local c=$3
    local proc_match=$4
    local n=$5

    echo -e "\n[Testing $name | C=$c | N=$n]" >> $OUTPUT_FILE
    echo "Uji $name dimulai..."
    
    # Jalankan ab di background
    ab -n $n -c $c $url > temp_ab.txt 2>&1 &
    local ab_pid=$!
    
    # Sampling RAM tertingginya
    local max_ram=0
    while kill -0 $ab_pid 2>/dev/null; do
        local current_ram_kb=$(ps aux | grep "$proc_match" | grep -v grep | awk '{sum+=$6} END {print sum}')
        if [[ ! -z "$current_ram_kb" ]] && [[ "$current_ram_kb" -gt "$max_ram" ]]; then
            max_ram=$current_ram_kb
        fi
        sleep 0.3 # Sampling lebih cepat biar akurat
    done
    
    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # Catat statistik
    if grep -q "Failed requests:        [1-9]" temp_ab.txt; then
        echo "!!! ALERT: ADA FAILED REQUESTS !!!" >> $OUTPUT_FILE
        grep "Failed requests" temp_ab.txt >> $OUTPUT_FILE
    fi
    
    grep -E "Requests per second|Time per request|Transfer rate|longest request" temp_ab.txt >> $OUTPUT_FILE
    echo "Peak RAM Usage: $final_ram_mb MB" >> $OUTPUT_FILE
    echo "-------------------------------------------------" >> $OUTPUT_FILE
    rm temp_ab.txt
}

# Naikkan ulimit
ulimit -n 10000 2>/dev/null

for c in "${CONCURRENCY[@]}"; do
    if [ $c -lt 100 ]; then n=5000; elif [ $c -lt 500 ]; then n=10000; else n=20000; fi

    echo ">>> Menguji Beban: $c Concurrent (Total $n req)..."
    
    # 1. Tes Apache
    run_bench "APACHE" $URL_APACHE $c "apache2" $n
    
    # 2. Tes Nginx
    run_bench "NGINX" $URL_NGINX $c "nginx" $n
    
    # 3. Tes Halmos (Sesuaikan path binary kamu)
    run_bench "HALMOS" $URL_HALMOS $c "./bin/halmos" $n
done

echo -e "\n=================================================" >> $OUTPUT_FILE
echo "Benchmark Selesai! Lihat hasil di: $OUTPUT_FILE"
echo "=================================================" >> $OUTPUT_FILE