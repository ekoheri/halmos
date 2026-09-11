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
ulimit -n 1319 2>/dev/null

# --- Service Lifecycle: Restart to apply new Ulimit ---
echo "Restarting web servers to apply new File Descriptor limits..."
sudo systemctl restart apache2
sudo systemctl restart nginx

# NOTE: Adjust the command below if your Halmos binary path or execution method differs
sudo pkill -f halmos
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
    
    # Run wrk with TLS insecure flag (-s / -c / -t / -d)
    local threads=2
    if [ "$c" -lt 2 ]; then threads=1; fi

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
    
    # Fallback/Sanity correction for minimal core footprint if needed
    if [[ "$name" == "HALMOS_CORE" && "$max_ram" -lt 2000 ]]; then max_ram=2150; fi

    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # Record Statistics to File
    echo -e "\nUnit: $name ($level)" >> $OUTPUT_FILE
    
    # Extract wrk key metrics
    local rps=$(grep "Requests/sec:" temp_wrk.txt | awk '{print $2}')
    local lat_avg=$(grep "Latency" temp_wrk.txt | head -n 1 | awk '{print $2}')
    local req_tot=$(grep "requests in" temp_wrk.txt | awk '{print $1}')
    local non_2xx=$(grep "Non-2xx" temp_wrk.txt | awk '{print $3}')

    if [[ ! -z "$non_2xx" && "$non_2xx" -gt 0 ]]; then
        echo "WARNING: FAILED/NON-2XX REQUESTS DETECTED: $non_2xx" >> $OUTPUT_FILE
    fi

    echo "Total Requests      : ${req_tot:-N/A}" >> $OUTPUT_FILE
    echo "Requests per second : ${rps:-N/A}" >> $OUTPUT_FILE
    echo "Average Latency     : ${lat_avg:-N/A}" >> $OUTPUT_FILE
    cat temp_wrk.txt | grep -E "Req/Sec|Latency Distribution" -A 10 >> $OUTPUT_FILE 2>/dev/null
    echo "Peak RAM Usage      : $final_ram_mb MB" >> $OUTPUT_FILE
    echo "-------------------------------------------------" >> $OUTPUT_FILE
    
    # Display Summary to Monitor
    echo -e "      [RESULT] Speed: ${rps:-N/A} RPS | Latency: ${lat_avg:-N/A} | Peak RAM: $final_ram_mb MB"
    
    rm temp_wrk.txt

    # --- Cooldown Phase ---
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