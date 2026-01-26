#!/bin/bash

# --- Timestamp for Unique Filename ---
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Target Configuration ---
# Pastikan domain testing.com sudah ada di /etc/hosts atau ganti ke localhost
URL_HALMOS="http://localhost:8080/test_dhe.php?mode=lib"
URL_APACHE="http://localhost:81/test_dhe.php?mode=lib"
URL_NGINX="http://localhost/test_dhe.php?mode=lib"

# --- Research Parameters (Sesuai Permintaan) ---
# Kita pasangkan n dan c secara sejajar dalam loop nanti
N_LEVELS=(10 50 100)
C_LEVELS=(5 25 50)
OUTPUT_FILE="performance_report_${TIMESTAMP}.txt"
RESTART_FPM="sudo systemctl restart php7.3-fpm"

# --- Report Header ---
echo "=================================================================" > $OUTPUT_FILE
echo " PERFORMANCE EVALUATION: HALMOS-CORE VS NGINX VS APACHE " >> $OUTPUT_FILE
echo "=================================================================" >> $OUTPUT_FILE
echo "Workload Profile  : Diffie-Hellman Ephemeral (DHE) 2048-bit" >> $OUTPUT_FILE
echo "Test Timestamp    : $(date)" >> $OUTPUT_FILE
echo "-----------------------------------------------------------------" >> $OUTPUT_FILE

run_benchmark() {
    local label=$1
    local url=$2
    local n=$3
    local c=$4
    
    local proc_pattern=""
    if [[ "$label" == *"HALMOS"* ]]; then proc_pattern="halmos"; 
    elif [[ "$label" == *"NGINX"* ]]; then proc_pattern="nginx"; 
    else proc_pattern="apache2"; fi

    echo "[RESEARCH] Testing $label | N=$n C=$c..."
    echo "TARGET: $label | TOTAL_REQ (n): $n | CONCURRENCY (c): $c" >> $OUTPUT_FILE
    
    # Jalankan ab
    ab -n $n -c $c "$url" > temp_ab.txt 2>&1 &
    local ab_pid=$!
    
    # --- Monitoring Peak RAM ---
    local max_ram_kb=0
    while kill -0 $ab_pid 2>/dev/null; do
        local current_ram=$(ps -o rss= -p $(pgrep -n "$proc_pattern") | xargs)
        if [[ ! -z "$current_ram" ]] && [[ "$current_ram" -gt "$max_ram_kb" ]]; then
            max_ram_kb=$current_ram
        fi
        sleep 0.1 
    done
    
    local peak_mem_mb=$(echo "scale=2; $max_ram_kb / 1024" | bc)
    
    # Ambil data penting dari hasil AB
    grep -E "Requests per second|Time per request:|99%|Failed requests" temp_ab.txt >> $OUTPUT_FILE
    echo "Peak RAM Utilization: $peak_mem_mb MB" >> $OUTPUT_FILE
    echo "-----------------------------------------------------------------" >> $OUTPUT_FILE
    rm temp_ab.txt
}

# --- Execution Phase ---

# List Server yang akan diuji
SERVERS=("APACHE_HTTPD" "NGINX_STABLE" "HALMOS_ENGINE")
URLS=("$URL_APACHE" "$URL_NGINX" "$URL_HALMOS")

for i in "${!SERVERS[@]}"; do
    SERVER_NAME=${SERVERS[$i]}
    SERVER_URL=${URLS[$i]}
    
    echo "Starting evaluation for $SERVER_NAME..."
    
    # Loop melalui pasangan N dan C
    for j in "${!N_LEVELS[@]}"; do
        N=${N_LEVELS[$j]}
        C=${C_LEVELS[$j]}
        
        # Bersihkan lingkungan sebelum test
        $RESTART_FPM && sleep 2
        
        run_benchmark "$SERVER_NAME" "$SERVER_URL" $N $C
        
        # Cooldown agar CPU adem
        sleep 3
    done
done

echo "[COMPLETED] Research data saved to: $OUTPUT_FILE"