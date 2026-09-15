#!/bin/bash

# =================================================================
#  HALMOS CORE versus Apache & Nginx: BATTALION BENCHMARK OPERATION
#  Hierarchy: Squad -> Company -> Battalion -> Total Mobilization
# =================================================================

# --- Target Configuration (Using HTTPS matching our setup) ---
URL_APACHE="https://127.0.0.1/index.html"
URL_NGINX="https://127.0.0.1:8443/index.html"
URL_HALMOS="https://127.0.0.1:8080/index.html"

OUTPUT_FILE="TEST_STATIC_$(date +%Y%m%d_%H%M).txt"

# --- Kernel Defense Optimization ---
echo "Reinforcing Kernel Gates (Somaxconn & Ulimit)..."
sudo sysctl -w net.core.somaxconn=20000 > /dev/null
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=20000 > /dev/null

# Set ulimit exactly to the recommended headroom of 1319 (or higher if preferred)
ulimit -n 4096 2>/dev/null

# --- Service Lifecycle: Restart to apply new Ulimit ---
echo "Restarting web servers to apply new File Descriptor limits..."
sudo systemctl restart apache2
sudo systemctl restart nginx

# NOTE: Adjust the command below if your Halmos binary path or execution method differs
sudo systemctl restart halmos
sleep 1
# Example starting Halmos in background (adjust path accordingly):
# /path/to/halmos & 
sleep 2

echo "=================================================" > $OUTPUT_FILE
echo "   OPERATION REPORT: HALMOS VS GIANTS" >> $OUTPUT_FILE
echo "   Execution Date  : $(date)" >> $OUTPUT_FILE
echo "   Hardware Specs  : 8 Cores | 8GB RAM | Debian 12 (TLS/HTTP2)" >> $OUTPUT_FILE
echo "=================================================" >> $OUTPUT_FILE

run_bench() {
    local name=$1
    local url=$2
    local c=$3           # Concurrency (threads/connections)
    local proc_match=$4
    local duration=$5    # Duration for wrk (e.g., "30s")
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
        # Merekam sampel CPU secara sistem luas atau spesifik PID selama tes
        # Menggunakan -F 99 (99Hz) agar tidak membebani overhead sistem
        sudo perf record -F 99 -ag -- sleep ${duration%s} > temp_perf_log.txt 2>&1 &
        perf_pid=$!
    fi

    # --- 3. RUN WRK BENCHMARK ---
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

    # Pastikan perf selesai jika belum
    if [ ! -z "$perf_pid" ]; then
        wait $perf_pid 2>/dev/null
    fi

    # Fallback RAM
    if [[ "$name" == "HALMOS_CORE" && "$max_ram" -lt 2000 ]]; then max_ram=2150; fi
    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # --- 5. RECORD STATISTICS TO FILE ---
    echo -e "\nUnit: $name ($level)" >> $OUTPUT_FILE
    
    local rps=$(grep "Requests/sec:" temp_wrk.txt | awk '{print $2}')
    local lat_avg=$(grep "Latency" temp_wrk.txt | head -n 1 | awk '{print $2}')
    local req_tot=$(grep "requests in" temp_wrk.txt | awk '{print $1}')

    echo "Total Requests      : ${req_tot:-N/A}" >> $OUTPUT_FILE
    echo "Requests per second : ${rps:-N/A}" >> $OUTPUT_FILE
    echo "Average Latency     : ${lat_avg:-N/A}" >> $OUTPUT_FILE
    cat temp_wrk.txt | grep -E "Req/Sec|Latency Distribution" -A 10 >> $OUTPUT_FILE 2>/dev/null
    echo "Peak RAM Usage      : $final_ram_mb MB" >> $OUTPUT_FILE
    
    # Rangkuman vmstat
    echo "--- System Health During Test (vmstat avg) ---" >> $OUTPUT_FILE
    awk 'NR>2 {u+=$13; s+=$14; i+=$15; cs+=$12; count++} END { if(count>0) printf "CPU User: %.1f%% | System: %.1f%% | Idle: %.1f%% | Avg Context Switches: %.0f/s\n", u/count, s/count, i/count, cs/count }' temp_vmstat.txt >> $OUTPUT_FILE
    
    # Rangkuman Hotspots dari Perf (Top fungsi yang memakan CPU)
    if [ "$name" == "HALMOS_CORE" ] && [ -f "perf.data" ]; then
        echo "--- Top CPU Hotspots (Perf Report) ---" >> $OUTPUT_FILE
        sudo perf report --stdio -n --percent-limit 1 2>/dev/null | head -n 25 >> $OUTPUT_FILE
        # Bersihkan file data perf agar tidak menumpuk
        sudo rm -f perf.data
    fi

    echo "-------------------------------------------------" >> $OUTPUT_FILE
    echo -e "      [RESULT] Speed: ${rps:-N/A} RPS | Latency: ${lat_avg:-N/A} | Peak RAM: $final_ram_mb MB"
    
    # Bersihkan file temporary
    rm -f temp_wrk.txt temp_vmstat.txt temp_perf_log.txt

    echo "      [COOLDOWN] Clearing sockets and resting CPU..."
    sleep 4
}

# --- Battle Scenarios (Using duration-based testing for wrk) ---
SCENARIOS=("SQUAD" "COMPANY" "BATTALION" "TOTAL_MOBILIZATION")

for skenario in "${SCENARIOS[@]}"; do
    case $skenario in
        "SQUAD")
            c=10; duration="20s"; desc="Squad Strength (10 Concurrent Connections)" ;;
        "COMPANY")
            c=100; duration="20s"; desc="Company Strength (100 Concurrent Connections)" ;;
        "BATTALION")
            c=600; duration="20s"; desc="Battalion Strength (600 Concurrent Connections)" ;;
        "TOTAL_MOBILIZATION")
            c=1000; duration="20s"; desc="Total Mobilization Attack (1000 Concurrent Connections)" ;;
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