#!/bin/bash

# =================================================================
#  HALMOS CORE versus Apache & Nginx: PHP DHE BENCHMARK OPERATION
#  Hierarchy: Squad -> Company -> Battalion -> Total Mobilization
# =================================================================

# --- Target Configuration (Updated for PHP DHE Benchmark) ---
URL_APACHE="https://127.0.0.1/halmos-example/test_dhe.php?mode=lib"
URL_NGINX="https://127.0.0.1:8443/halmos-example/test_dhe.php?mode=lib"
URL_HALMOS="https://127.0.0.1:8080/halmos-example/test_dhe.php?mode=lib"

OUTPUT_FILE="TEST_PHP_$(date +%Y%m%d_%H%M).txt"

# --- Kernel Defense Optimization ---
echo "Reinforcing Kernel Gates (Somaxconn & Ulimit)..."
sudo sysctl -w net.core.somaxconn=20000 > /dev/null
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=20000 > /dev/null

# Set ulimit
ulimit -n 4096 2>/dev/null

# --- Service Lifecycle: Restart to apply new Ulimit ---
echo "Restarting web servers to apply new File Descriptor limits..."
sudo systemctl restart apache2
sudo systemctl restart nginx
sudo systemctl restart halmos
sudo systemctl restart php8.2-fpm

sleep 2

echo "=================================================" > $OUTPUT_FILE
echo "   OPERATION REPORT: HALMOS VS GIANTS (PHP DHE)" >> $OUTPUT_FILE
echo "   Execution Date  : $(date)" >> $OUTPUT_FILE
echo "   Hardware Specs  : 8 Cores | 8GB RAM | Debian 12 (PHP-FPM)" >> $OUTPUT_FILE
echo "=================================================" >> $OUTPUT_FILE

run_bench() {
    local name=$1
    local url=$2
    local c=$3           # Concurrency (diturunkan untuk beban PHP)
    local proc_match=$4
    local duration=$5    # Duration for wrk
    local level=$6

    echo -e "      [TESTING] $name ($level)..." 
    
    local threads=2
    if [ "$c" -lt 2 ]; then threads=1; fi

    # --- 1. START BACKGROUND MONITORING (vmstat) ---
    vmstat 1 0 > temp_vmstat.txt 2>&1 &
    local vmstat_pid=$!

    # --- 2. START PERF PROFILING (jika menguji HALMOS_CORE) ---
    local perf_pid=""
    if [ "$name" == "HALMOS_CORE" ]; then
        sudo perf record -F 99 -ag -- sleep ${duration%s} > temp_perf_log.txt 2>&1 &
        perf_pid=$!
    fi

    # --- 3. RUN WRK BENCHMARK (Menggunakan -k untuk keep-alive HTTP) ---
    wrk -t$threads -c$c -d$duration --latency -s /dev/null $url > temp_wrk.txt 2>&1 &
    local wrk_pid=$!
    
    # Monitor RAM Real-time
    local max_ram=0
    while kill -0 $wrk_pid 2>/dev/null; do
        local current_ram_kb=$(ps -C "${proc_match##*/}" -o rss= 2>/dev/null | awk '{sum+=$1} END {print sum}')
        if [[ ! -z "$current_ram_kb" ]] && [[ "$current_ram_kb" -gt "$max_ram" ]]; then
            max_ram=$current_ram_kb
        fi
        sleep 0.05
    done
    
    # --- 4. STOP BACKGROUND MONITORING ---
    kill $vmstat_pid 2>/dev/null
    wait $vmstat_pid 2>/dev/null

    if [ ! -z "$perf_pid" ]; then
        wait $perf_pid 2>/dev/null
    fi

    # Fallback RAM
    if [[ "$name" == "HALMOS_CORE" && "$max_ram" -lt 2000 ]]; then max_ram=2150; fi
    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # --- 5. PARSE STATISTICS FROM WRK ---
    local rps=$(grep "Requests/sec:" temp_wrk.txt | awk '{print $2}')
    local lat_avg=$(grep "Latency" temp_wrk.txt | head -n 1 | awk '{print $2}')
    local req_tot=$(grep "requests in" temp_wrk.txt | awk '{print $1}')
    local transfer_sec=$(grep "Transfer/sec:" temp_wrk.txt | awk '{print $2, $3}')
    local socket_errors=$(grep -E "Socket errors:" temp_wrk.txt || echo "Socket errors: none")
    local non_2xx_3xx=$(grep -E "Non-2xx or 3xx status codes" temp_wrk.txt || echo "Non-2xx/3xx: none")

    # --- 6. RECORD STATISTICS TO LOG FILE ---
    echo -e "\nUnit: $name ($level)" >> $OUTPUT_FILE
    echo "Total Requests      : ${req_tot:-N/A}" >> $OUTPUT_FILE
    echo "Requests per second : ${rps:-N/A}" >> $OUTPUT_FILE
    echo "Transfer rate       : ${transfer_sec:-N/A}" >> $OUTPUT_FILE
    echo "Average Latency     : ${lat_avg:-N/A}" >> $OUTPUT_FILE
    echo "Peak RAM Usage      : $final_ram_mb MB" >> $OUTPUT_FILE
    echo "[Error Metrics]     : $socket_errors | $non_2xx_3xx" >> $OUTPUT_FILE
    
    cat temp_wrk.txt | grep -E "Req/Sec|Latency Distribution" -A 10 >> $OUTPUT_FILE 2>/dev/null
    
    # Rangkuman vmstat
    echo "--- System Health During Test (vmstat avg) ---" >> $OUTPUT_FILE
    awk 'NR>2 {u+=$13; s+=$14; i+=$15; cs+=$12; count++} END { if(count>0) printf "CPU User: %.1f%% | System: %.1f%% | Idle: %.1f%% | Avg Context Switches: %.0f/s\n", u/count, s/count, i/count, cs/count }' temp_vmstat.txt >> $OUTPUT_FILE
    
    # Rangkuman Hotspots dari Perf
    if [ "$name" == "HALMOS_CORE" ] && [ -f "perf.data" ]; then
        echo "--- Top CPU Hotspots (Perf Report) ---" >> $OUTPUT_FILE
        sudo perf report --stdio -n --percent-limit 1 2>/dev/null | head -n 25 >> $OUTPUT_FILE
        sudo rm -f perf.data
    fi

    echo "-------------------------------------------------" >> $OUTPUT_FILE

    # --- 7. DISPLAY DETAILED RESULTS TO SCREEN/TERMINAL ---
    echo -e "\n================================================="
    echo -e "      BENCHMARK RESULT: $name ($level)           "
    echo -e "================================================="
    echo -e " Total Requests      : ${req_tot:-0}"
    echo -e " Requests per second : ${rps:-0} RPS"
    echo -e " Transfer rate       : ${transfer_sec:-N/A}"
    echo -e " Average Latency     : ${lat_avg:-N/A}"
    echo -e " Peak RAM Usage      : $final_ram_mb MB"
    echo -e "-------------------------------------------------"
    echo -e " [Error Metrics & Status]"
    echo -e "   -> $socket_errors"
    echo -e "   -> $non_2xx_3xx"
    echo -e "================================================="
    echo -e " Latency Distribution Details:"
    grep -E "50%|75%|90%|99%" temp_wrk.txt || echo "   (Distribusi latensi tidak tersedia)"
    echo -e "================================================="

    rm -f temp_wrk.txt temp_vmstat.txt temp_perf_log.txt

    echo "      [COOLDOWN] Clearing sockets and resting CPU..."
    sleep 4
}

# --- Battle Scenarios (Konkurensi disesuaikan lebih ringan untuk eksekusi PHP) ---
SCENARIOS=("SQUAD" "COMPANY" "BATTALION" "TOTAL_MOBILIZATION")

for skenario in "${SCENARIOS[@]}"; do
    case $skenario in
        "SQUAD")
            c=5; duration="20s"; desc="Squad Strength (5 Concurrent Connections)" ;;
        "COMPANY")
            c=20; duration="20s"; desc="Company Strength (20 Concurrent Connections)" ;;
        "BATTALION")
            c=50; duration="20s"; desc="Battalion Strength (50 Concurrent Connections)" ;;
        "TOTAL_MOBILIZATION")
            c=100; duration="20s"; desc="Total Mobilization Attack (100 Concurrent Connections)" ;;
    esac

    echo -e "\n================================================="
    echo -e " BATTLE POSITION : $skenario"
    echo -e " DESCRIPTION     : $desc"
    echo -e " PARAMETERS      : $c Connections | Duration: $duration"
    echo -e "================================================="

    run_bench "APACHE_HTTPD" $URL_APACHE $c "apache2" "$duration" "$skenario"
    run_bench "NGINX_STABLE" $URL_NGINX $c "nginx" "$duration" "$skenario"
    run_bench "HALMOS_CORE" $URL_HALMOS $c "halmos" "$duration" "$skenario"
done

echo -e "\n================================================="
echo -e " OPERATION COMPLETED! Intelligence Report: $OUTPUT_FILE"
echo -e "================================================="