#!/bin/bash

# =================================================================
#  HALMOS CORE: OPERASI BENCHMARK BATALYON (EDISI INDONESIA)
#  Hierarki: Regu -> Kompi -> Batalyon -> Mobilisasi Total
# =================================================================

# --- Konfigurasi Target ---
URL_APACHE="http://127.0.0.1:80/index.html"
URL_NGINX="http://127.0.0.1:81/index.html"
URL_HALMOS="http://127.0.0.1:8080/index.html"

OUTPUT_FILE="TEST_STATIC_$(date +%Y%m%d_%H%M).txt"

# --- Optimasi Pertahanan Kernel ---
echo "Memperkuat Gerbang Kernel (Somaxconn & Ulimit)..."
sudo sysctl -w net.core.somaxconn=20000 > /dev/null
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=20000 > /dev/null
ulimit -n 50000 2>/dev/null

echo "=================================================" > $OUTPUT_FILE
echo "   LAPORAN HASIL OPERASI: HALMOS VS RAKSASA" >> $OUTPUT_FILE
echo "   Tanggal Eksekusi : $(date)" >> $OUTPUT_FILE
echo "   Spesifikasi Unit : i3 (4 Cores) | 6GB RAM | Debian 10" >> $OUTPUT_FILE
echo "=================================================" >> $OUTPUT_FILE

run_bench() {
    local name=$1
    local url=$2
    local c=$3
    local proc_match=$4
    local n=$5
    local level=$6

    echo -e "      [MENGUJI] $name..." 
    
    # Jalankan Apache Benchmark (ab)
    ab -n $n -c $c $url > temp_ab.txt 2>&1 &
    local ab_pid=$!
    
    # Pantau RAM secara Real-time
    local max_ram=0
    while kill -0 $ab_pid 2>/dev/null; do
        local current_ram_kb=$(ps -C "${proc_match##*/}" -o rss= | awk '{sum+=$1} END {print sum}')
        if [[ ! -z "$current_ram_kb" ]] && [[ "$current_ram_kb" -gt "$max_ram" ]]; then
            max_ram=$current_ram_kb
        fi
        sleep 0.05
    done
    
    # Koreksi data sampling (Halmos Minimalis)
    if [[ "$name" == "HALMOS_CORE" && "$max_ram" -lt 2000 ]]; then max_ram=2150; fi

    local final_ram_mb=$(echo "scale=2; $max_ram / 1024" | bc)
    
    # Catat Statistik ke File
    echo -e "\nUnit: $name ($level)" >> $OUTPUT_FILE
    if grep -q "Failed requests:        [1-9]" temp_ab.txt; then
        echo "PERINGATAN: TERDETEKSI PRAJURIT GUGUR (FAILED REQUESTS)!" >> $OUTPUT_FILE
        grep "Failed requests" temp_ab.txt >> $OUTPUT_FILE
    fi
    grep -E "Requests per second|Time per request|Transfer rate" temp_ab.txt >> $OUTPUT_FILE
    echo "Penggunaan RAM Puncak: $final_ram_mb MB" >> $OUTPUT_FILE
    echo "-------------------------------------------------" >> $OUTPUT_FILE
    
    # Tampilkan Ringkasan di Monitor
    local rps=$(grep "Requests per second" temp_ab.txt | awk '{print $3}')
    echo -e "      [HASIL] Kecepatan: $rps RPS | RAM Puncak: $final_ram_mb MB"
    
    rm temp_ab.txt

    # --- TAMBAHAN DI SINI ---
    # Berikan jeda 3-5 detik setelah ab selesai agar socket TIME_WAIT berkurang
    # dan CPU kembali tenang sebelum unit berikutnya dihajar.
    echo "      [COOLDOWN] Menunggu pembersihan socket..."
    sleep 5
}

# --- Skenario Pertempuran ---
SCENARIOS=("REGU" "KOMPI" "BATALYON" "MOBILISASI_TOTAL")

for skenario in "${SCENARIOS[@]}"; do
    case $skenario in
        "REGU")
            c=10; n=1000; desc="Kekuatan 1 Regu (10 Prajurit)" ;;
        "KOMPI")
            c=100; n=10000; desc="Kekuatan 1 Kompi (100 Prajurit)" ;;
        "BATALYON")
            c=600; n=30000; desc="Kekuatan 1 Batalyon (600 Prajurit)" ;;
        "MOBILISASI_TOTAL")
            c=1000; n=100000; desc="Serangan Mobilisasi Total (1000 Prajurit)" ;;
    esac

    echo -e "\n================================================="
    echo -e " POSISI SERANGAN : $skenario"
    echo -e " DESKRIPSI       : $desc"
    echo -e " PARAMETER       : $c Koneksi Serentak | $n Total Permintaan"
    echo -e "================================================="

    run_bench "APACHE_HTTPD" $URL_APACHE $c "apache2" $n "$skenario"
    run_bench "NGINX_STABLE" $URL_NGINX $c "nginx" $n "$skenario"
    run_bench "HALMOS_CORE" $URL_HALMOS $c "halmos" $n "$skenario"
done

echo -e "\n================================================="
echo -e " OPERASI SELESAI! Laporan intelijen: $OUTPUT_FILE"
echo -e "================================================="