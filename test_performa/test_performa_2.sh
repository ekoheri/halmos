#!/bin/bash

# --- Skenario Militer Diperluas ---
# 1 Regu (Squad)     : Concurrency 12, Total 120
# 2 Regu (Section)   : Concurrency 24, Total 500  <-- Tambahan Baru
# 1 Kompi (Company)  : Concurrency 100, Total 1000
SCENARIO_NAMES=("1_REGU_SQUAD" "2_REGU_SECTION" "1_KOMPI_COMPANY")
N_LEVELS=(120 500 1000)
C_LEVELS=(12 24 100)

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
URL_HALMOS="http://localhost:8080/test_dhe.php?mode=lib"
URL_APACHE="http://localhost:81/test_dhe.php?mode=lib"
URL_NGINX="http://localhost/test_dhe.php?mode=lib"
OUTPUT_FILE="TEST_DYNAMIC_v2_${TIMESTAMP}.txt"

# --- OPTIMASI LINUX ---
echo "[SYSTEM] Memperkuat benteng Linux (Doping Kernel)..."
sudo sysctl -w net.core.somaxconn=20000 > /dev/null
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" > /dev/null
ulimit -n 100000

# --- Report Header ---
echo "=================================================================" > $OUTPUT_FILE
echo "        MILITARY GRADE BENCHMARK: DHE 2048-BIT EXCHANGE v2       " >> $OUTPUT_FILE
echo "=================================================================" >> $OUTPUT_FILE
echo "Laptop Status: All Systems Go (High Performance Mode)" >> $OUTPUT_FILE
echo "-----------------------------------------------------------------" >> $OUTPUT_FILE

run_benchmark() {
    local label=$1
    local scenario=$2
    local url=$3
    local n=$4
    local c=$5
    
    local proc_pattern=""
    if [[ "$label" == *"HALMOS"* ]]; then proc_pattern="halmos"; 
    elif [[ "$label" == *"NGINX"* ]]; then proc_pattern="nginx"; 
    else proc_pattern="apache2"; fi

    echo "[ATTACK] $label - $scenario (N=$n, C=$c)..."
    echo "MISI: $scenario | TARGET: $label | REQ: $n | CONC: $c" >> $OUTPUT_FILE
    
    # Jalankan ab
    ab -n $n -c $c "$url" > temp_ab.txt 2>&1 &
    local ab_pid=$!
    
    # Monitoring RAM dengan sampling lebih cepat
    local max_ram_kb=0
    while kill -0 $ab_pid 2>/dev/null; do
        # Ambil RSS tertinggi dari proses yang cocok
        local current_ram=$(ps -o rss= -C "$proc_pattern" | awk '{sum+=$1} END {print sum}')
        if [[ ! -z "$current_ram" ]] && [[ "$current_ram" -gt "$max_ram_kb" ]]; then
            max_ram_kb=$current_ram
        fi
        sleep 0.02 
    done
    
    local peak_mem_mb=$(echo "scale=2; $max_ram_kb / 1024" | bc)
    
    grep -E "Requests per second|Time per request:|99%|Failed requests" temp_ab.txt >> $OUTPUT_FILE
    echo "Peak RAM Utilization: $peak_mem_mb MB" >> $OUTPUT_FILE
    echo "-----------------------------------------------------------------" >> $OUTPUT_FILE
    rm temp_ab.txt
}

SERVERS=("HALMOS_ENGINE" "NGINX_STABLE" "APACHE_HTTPD")
URLS=("$URL_HALMOS" "$URL_NGINX" "$URL_APACHE")

for j in "${!N_LEVELS[@]}"; do
    SCENARIO=${SCENARIO_NAMES[$j]}
    N=${N_LEVELS[$j]}
    C=${C_LEVELS[$j]}
    
    echo "--- MEMULAI OPERASI $SCENARIO ---"
    
    for i in "${!SERVERS[@]}"; do
        # Restart FPM & Server Target untuk memastikan lingkungan bersih
        sudo systemctl restart php-fpm > /dev/null 2>&1 || sudo systemctl restart php7.4-fpm > /dev/null 2>&1
        sleep 3
        
        run_benchmark "${SERVERS[$i]}" "$SCENARIO" "${URLS[$i]}" $N $C
        sleep 5 # Cooldown lebih lama agar CPU throttle kembali normal
    done
done

echo "[FINISH] Operasi Selesai. Data mentah tersimpan di: $OUTPUT_FILE"