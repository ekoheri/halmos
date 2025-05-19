#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "../include/pasaran.h"

const char *nama_bulan[] = {"Suro", "Sapar", "Mulud", "BakdaMulud", "JumadilAwal", "JumadilAkhir", "Rejeb", "Ruwah", "Poso", "Bodo", "Longkang", "Besar"};
int neptu_bulan[] = {7, 2, 3, 5, 6, 1, 2, 4, 5, 7, 1, 3};
const char *nama_hari[] = {"Ahad", "Senen", "Selasa", "Rebu", "Kemis", "Jumuah", "Setu"};
int neptu_hari[] = {5, 4, 3, 7, 8, 6, 9};
const char *nama_pasaran[] = {"Pon", "Wage", "Kliwon", "Legi", "Pahing"};
int neptu_pasaran[] = {5, 9, 7, 4, 8};
//https://www.scribd.com/doc/160155747/Aplikasi-Perhitungan-Wariga-Pada-Platform-Android
const char *nama_wuku[] = {"Sinta","Landhep","Wukir","Kurantil","Tolu","Gumbreg", 
    "Warigalit", "Warigagung","Julungwangi","Sungsang","Galungan","Kuningan",
    "Langkir", "Mandasiya","Julung pujut","Pahang", "Kuruwelut","Marakeh",
    "Tambir", "Medangkungan","Maktal", "Wuye","Manahil","Prangbakat",
    "Bala", "Wugu","Wayang", "Kulawu","Dukut","Watu Gunung"};
int neptu_wuku[] = {7, 1, 4, 6, 5, 8,
    9, 3, 7, 1, 4, 6,
    5, 8, 9, 3, 7, 1, 
    4, 6, 5, 8, 9, 3, 
    7, 1, 4, 6, 5, 8};
const char *nama_warsa[] = {"Be","Wawu","Jimakir","Alip","Ehe","Jimawal","Je","Dal"};
int neptu_warsa[] = {1, 5, 3, 7, 4, 2, 6, 3};

const char *nama_windu[] = {"Kuntara", "Sangara", "Sancaya", "Adi"};
int neptu_windu[] = {8, 9, 7, 6};

int intPart(double floatNum) {
    if (floatNum < -0.0000001) {
        return (int)ceil(floatNum - 0.0000001);
    } else {
        return (int)floor(floatNum + 0.0000001);
    }
}

int gregorianToJD(int month, int day, int year) {
    int a = intPart((14 - month) / 12);
    int y = year + 4800 - a;
    int m = month + 12 * a - 3;
    return day + intPart((153 * m + 2) / 5) + 365 * y + intPart(y / 4) - intPart(y / 100) + intPart(y / 400) - 32045;
}

char *masehi2jawa(const char* time_string) {
    char *result = (char *)malloc(128);

    // Parsing waktu dari string time_string
    int tahun, bulan, tanggal, jam, menit, detik, millis;

    // Parsing string waktu dengan format yang sesuai
    char temp_str[256];
    strncpy(temp_str, time_string, sizeof(temp_str));  // Copy untuk manipulasi

    // Langkah 1: Mengabaikan nama hari (misal "Tue,")
    char* token = strtok(temp_str, ", ");  // Dapatkan "Tue"
    
    // Langkah 2: Ambil tanggal
    token = strtok(NULL, " ");
    tanggal = atoi(token);

    // Langkah 3: Ambil bulan (misal "Dec")
    token = strtok(NULL, " ");
    char* bulan_str = token;

    // Mengkonversi bulan dari string ke angka
    if (strcmp(bulan_str, "Jan") == 0) bulan = 1;
    else if (strcmp(bulan_str, "Feb") == 0) bulan = 2;
    else if (strcmp(bulan_str, "Mar") == 0) bulan = 3;
    else if (strcmp(bulan_str, "Apr") == 0) bulan = 4;
    else if (strcmp(bulan_str, "May") == 0) bulan = 5;
    else if (strcmp(bulan_str, "Jun") == 0) bulan = 6;
    else if (strcmp(bulan_str, "Jul") == 0) bulan = 7;
    else if (strcmp(bulan_str, "Aug") == 0) bulan = 8;
    else if (strcmp(bulan_str, "Sep") == 0) bulan = 9;
    else if (strcmp(bulan_str, "Oct") == 0) bulan = 10;
    else if (strcmp(bulan_str, "Nov") == 0) bulan = 11;
    else if (strcmp(bulan_str, "Dec") == 0) bulan = 12;
    else {
        printf("Bulan tidak dikenali!\n");
        return NULL;
    }

    // Langkah 4: Ambil tahun
    token = strtok(NULL, " ");
    tahun = atoi(token);

    // Langkah 5: Ambil waktu (jam:menit:detik.milis)
    token = strtok(NULL, ":");
    jam = atoi(token);
    token = strtok(NULL, ":");
    menit = atoi(token);
    token = strtok(NULL, ".");
    detik = atoi(token);
    token = strtok(NULL, " ");
    millis = atoi(token);
    
    // Konversi masehi ke jawa
    int day = tanggal;
    int month = bulan;
    int year = tahun;
    int julian = gregorianToJD(month, day, year);

    if (julian >= 1937808 && julian <= 536838867) {
        int hijriDay, 
            hijriMonth, 
            hijriYear, 
            julianDay, 
            julianDayOffset, 
            hijriCycleCount, 
            hijriMonthIndex, 
            javaYear, 
            javaDayIndex,
            wukuIndex,
            warsaIndex,
            winduIndex;

        double monthPart;
        int dow = (julian + 1) % 7;

        monthPart = (month - 14) / 12.0;
        julianDay = intPart((1461 * (year + 4800 + intPart(monthPart))) / 4) +
                    intPart((367 * (month - 2 - 12 * intPart(monthPart))) / 12) -
                    intPart((3 * intPart((year + 4900 + intPart(monthPart)) / 100)) / 4) +
                    day - 32075;

        julianDayOffset = julianDay - 1948440 + 10632;
        hijriCycleCount = intPart((julianDayOffset - 1) / 10631);
        julianDayOffset = julianDayOffset - 10631 * hijriCycleCount + 354;
        hijriMonthIndex = intPart((10985 - julianDayOffset) / 5316) * intPart((50 * julianDayOffset) / 17719) +
                          intPart(julianDayOffset / 5670) * intPart((43 * julianDayOffset) / 15238);
        julianDayOffset = julianDayOffset - intPart((30 - hijriMonthIndex) / 15) * intPart((17719 * hijriMonthIndex) / 50) -
                          intPart(hijriMonthIndex / 16) * intPart((15238 * hijriMonthIndex) / 43) + 29;

        hijriMonth = intPart((24 * julianDayOffset) / 709);
        hijriDay = julianDayOffset - intPart((709 * hijriMonth) / 24);
        hijriYear = 30 * hijriCycleCount + hijriMonthIndex - 30;
        javaYear = hijriYear + 512;
        javaDayIndex = ((julian + 3) % 5 + 5) % 5; // Pastikan hasil modulo positif

        int selisih_hari = julian - gregorianToJD(12, 1, 1900);
        wukuIndex = (int)floor((selisih_hari % 210) / 7);
        /*int ijy = javaYear;
        warsaIndex = ijy;
		if (ijy >= 8) {
            while (ijy > 7) {
                ijy = ijy - 8;
                warsaIndex = ijy;
            }
		}*/

        winduIndex = javaYear % 4;

        warsaIndex = javaYear % 8;

        if (julian <= 1948439) hijriYear--;

        // Tampilkan hasil
        snprintf(result, 128, "%s(%d)%s(%d)%d%s(%d)%d%s(%d)%s(%d)%s(%d)%d%d%d%d", 
            nama_hari[dow],
            neptu_hari[dow],
            nama_pasaran[javaDayIndex],
            neptu_pasaran[javaDayIndex],
            hijriDay,
            nama_bulan[hijriMonth -1],
            neptu_bulan[hijriMonth -1], 
            javaYear, 
            nama_wuku[wukuIndex],
            neptu_wuku[wukuIndex],
            nama_windu[winduIndex],
            neptu_windu[winduIndex],
            nama_warsa[warsaIndex],
            neptu_warsa[warsaIndex],
            jam, 
            menit, 
            detik, 
            millis);
    } else {
        result = "Tanggal di luar jangkauan";
    }
    return result;
}
