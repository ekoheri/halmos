#!/bin/bash

URL="https://localhost:8080/halmos-example/test_dhe.php?mode=lib"
TOTAL_REQUESTS=30
CONCURRENCY=10  # Dibatasi 5 paralel agar pool FPM aman dan tidak rebutan

echo "=== Memulai Uji Coba Stabil Halmos HTTP/2 ==="
echo "Target      : $URL"
echo "Total Req   : $TOTAL_REQUESTS"
echo "Konkurensi  : $CONCURRENCY"
echo "--------------------------------------------------"

start_time=$(date +%s.%N)

# Menjalankan menggunakan xargs untuk kontrol konkurensi (-P)
seq 1 $TOTAL_REQUESTS | xargs -n 1 -P $CONCURRENCY bash -c '
    url="$0"
    t_start=$(date +%s.%N)
    code=$(curl -s -k --http2 -o /dev/null -w "%{http_code}" "$url")
    t_end=$(date +%s.%N)
    t_diff=$(echo "($t_end - $t_start) * 1000" | bc)
    
    if [ "$code" = "200" ]; then
        echo "SUCCESS $t_diff"
    else
        echo "FAIL $code"
    fi
' "$URL" | awk '
    BEGIN { success=0; fail=0; total_time=0; }
    /^SUCCESS/ { success++; total_time += $2; }
    /^FAIL/ { fail++; }
    END {
        print "--------------------------------------------------"
        print "Hasil Pengujian:"
        print "Sukses (200)   : " success
        print "Gagal/Error    : " fail
        if (success > 0) {
            print "Latensi Rata-rata: " (total_time / success) " ms"
        }
    }
'

end_time=$(date +%s.%N)
total_duration=$(echo "$end_time - $start_time" | bc)
echo "Waktu Eksekusi : ${total_duration} detik"
echo "=================================================="