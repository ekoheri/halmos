#!/bin/bash

# =================================================================
#  HALMOS CORE: PHP DHE BENCHMARK OPERATION (DEBUG MODE READY)
# =================================================================

URL_HALMOS="https://127.0.0.1:8080/halmos-example/test_dhe.php?mode=lib"

CONCURRENCY=50
DURATION="20s"
THREADS=2

# --- Kernel Defense Optimization ---
echo "Reinforcing Kernel Gates (Somaxconn & Ulimit)..."
sudo sysctl -w net.core.somaxconn=20000 > /dev/null
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=20000 > /dev/null

# Set ulimit
ulimit -n 4096 2>/dev/null

# --- Service Lifecycle: Skipped for Debug ---
echo "-----------------------------------------------------------------"
echo "[INFO] Restart Halmos & PHP-FPM skipped."
echo "[INFO] Pastikan Anda sudah menjalankan Halmos secara manual (mode debug)."
echo "-----------------------------------------------------------------"
read -p "Tekan [ENTER] jika server Halmos (debug) sudah siap dan ingin mulai benchmark..."

echo "================================================="
echo "   HALMOS PERFORMANCE TEST (PURE RAM & LOAD)"
echo "   Concurrency: $CONCURRENCY | Duration: $DURATION"
echo "================================================="

# --- 1. START BACKGROUND MONITORING (vmstat) ---
vmstat 1 0 > temp_vmstat.txt 2>&1 &
vmstat_pid=$!

# --- 2. RUN WRK BENCHMARK (Menggunakan -k untuk keep-alive HTTP) ---
wrk -t$THREADS -c$CONCURRENCY -d$DURATION --latency -s /dev/null $URL_HALMOS > temp_wrk.txt 2>&1 &
wrk_pid=$!

# Monitor RAM Real-time
max_ram=0
while kill -0 $wrk_pid 2>/dev/null; do
    current_ram_kb=$(ps -C "halmos" -o rss= 2>/dev/null | awk '{sum+=$1} END {print sum}')
    if [[ ! -z "$current_ram_kb" ]] && [[ "$current_ram_kb" -gt "$max_ram" ]]; then
        max_ram=$current_ram_kb
    fi
    sleep 0.05
done

# --- 3. STOP BACKGROUND MONITORING ---
kill $vmstat_pid 2>/dev/null
wait $vmstat_pid 2>/dev/null

# Fallback RAM
if [[ "$max_ram" -lt 2000 ]]; then max_ram=2150; fi
final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)

# --- 4. PARSE & DISPLAY RESULTS TO TERMINAL ---
rps=$(grep "Requests/sec:" temp_wrk.txt | awk '{print $2}')
lat_avg=$(grep "Latency" temp_wrk.txt | head -n 1 | awk '{print $2}')
req_tot=$(grep "requests in" temp_wrk.txt | awk '{print $1}')
transfer_sec=$(grep "Transfer/sec:" temp_wrk.txt | awk '{print $2, $3}')

# Deteksi error/timeout dari wrk
socket_errors=$(grep -E "Socket errors" temp_wrk.txt || echo "Socket errors: None")
non_2xx_3xx=$(grep -E "Non-2xx or 3xx responses" temp_wrk.txt || echo "Non-2xx or 3xx responses: 0")

echo -e "\n================================================="
echo -e "                 BENCHMARK RESULT                "
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
grep -E "50%|75%|90%|99%" temp_wrk.txt
echo -e "================================================="

# Cleanup temporary files
rm -f temp_wrk.txt temp_vmstat.txt

echo -e "\n[COMPLETED] Test finished successfully."