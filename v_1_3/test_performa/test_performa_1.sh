#!/bin/bash

# --- Target Configuration ---
URL_APACHE="http://127.0.0.1:80/index.html"
URL_NGINX="http://127.0.0.1:81/index.html"
URL_HALMOS="http://127.0.0.1:8080/index.html"

# Concurrency Scenarios: Low (10), Moderate (100), Heavy (500), Extreme (1000)
CONCURRENCY=(10 100 500 1000) 
OUTPUT_FILE="BENCHMARK_REPORT_$(date +%Y%m%d_%H%M).txt"

# Ensure 'bc' is installed for floating point arithmetic
if ! command -v bc &> /dev/null; then
    echo "Error: 'bc' not found. Please install via: sudo apt install bc"
    exit 1
fi

echo "=================================================" > $OUTPUT_FILE
echo "   EXPERIMENTAL COMPARISON: APACHE VS NGINX VS HALMOS" >> $OUTPUT_FILE
echo "   Execution Date : $(date)" >> $OUTPUT_FILE
echo "   Test Scenario  : Incremental Concurrency Load" >> $OUTPUT_FILE
echo "=================================================" >> $OUTPUT_FILE

get_ram() {
    local proc_match=$1
    # Extract RSS (Resident Set Size) - Physical RAM
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

    echo -e "\n[Profiling $name | C=$c | N=$n]" >> $OUTPUT_FILE
    echo "Starting evaluation for $name..."
    
    # Execute Apache Benchmark in background
    ab -n $n -c $c $url > temp_ab.txt 2>&1 &
    local ab_pid=$!
    
    # Peak RAM Sampling logic
    local max_ram=0
    while kill -0 $ab_pid 2>/dev/null; do
        local current_ram_kb=$(ps aux | grep "$proc_match" | grep -v grep | awk '{sum+=$6} END {print sum}')
        if [[ ! -z "$current_ram_kb" ]] && [[ "$current_ram_kb" -gt "$max_ram" ]]; then
            max_ram=$current_ram_kb
        fi
        sleep 0.3 # High-frequency sampling for better precision
    done
    
    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # Logging Statistics
    if grep -q "Failed requests:        [1-9]" temp_ab.txt; then
        echo "!!! CRITICAL ALERT: FAILED REQUESTS DETECTED !!!" >> $OUTPUT_FILE
        grep "Failed requests" temp_ab.txt >> $OUTPUT_FILE
    fi
    
    grep -E "Requests per second|Time per request|Transfer rate|longest request" temp_ab.txt >> $OUTPUT_FILE
    echo "Peak RAM Utilization: $final_ram_mb MB" >> $OUTPUT_FILE
    echo "-------------------------------------------------" >> $OUTPUT_FILE
    rm temp_ab.txt
}

# Optimize system limits for high concurrency
ulimit -n 10000 2>/dev/null

for c in "${CONCURRENCY[@]}"; do
    if [ $c -lt 100 ]; then n=5000; elif [ $c -lt 500 ]; then n=10000; else n=20000; fi

    echo ">>> Stress Test Progress: $c Concurrency ($n total requests)..."
    
    # 1. Evaluate Apache
    run_bench "APACHE_HTTPD" $URL_APACHE $c "apache2" $n
    
    # 2. Evaluate Nginx
    run_bench "NGINX_STABLE" $URL_NGINX $c "nginx" $n
    
    # 3. Evaluate Halmos (Proposed Engine)
    run_bench "HALMOS_CORE" $URL_HALMOS $c "./bin/halmos" $n
done

echo -e "\n=================================================" >> $OUTPUT_FILE
echo "Analysis Complete! Results saved to: $OUTPUT_FILE"
echo "=================================================" >> $OUTPUT_FILE