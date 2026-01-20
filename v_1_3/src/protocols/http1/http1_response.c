#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

/* Gunakan header wrapper yang sudah mencakup common dan http1 */
#include "http_common.h"
#include "http1_response.h"
#include "log.h"

/**********************************************************************
 * send_http1_headers()
 * ANALOGI :
 * Petugas AMBIL NOMOR ANTRIAN yang menyiapkan amplop balasan.
 *
 * Dia hanya menulis bagian KOP (header) surat:
 * - Status: "200 OK" → seperti cap “BERHASIL”
 * - Jenis isi: HTML / gambar / JSON
 * - Panjang isi: berapa gram berat paket
 * - Mau tutup loket atau tetap buka (keep-alive)
 *
 * Petugas ini TIDAK menyentuh isi surat,
 * hanya menyiapkan header/amplopnya saja.
 **********************************************************************/
static void send_http1_headers(int client_fd, const HalmosResponse *res, bool keep_alive) {
    // Perbesar ke 1024 supaya aman saat nambah banyak header security
    char header[1024]; 
    const char *conn_status = keep_alive ? "keep-alive" : "close";

    // Gunakan snprintf untuk mencegah buffer overflow
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Server: Halmos-Engine/1.0\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n" // Opsi: Bagus untuk dynamic content
        "\r\n", 
        res->status_code, res->status_message, 
        res->mime_type, res->length, conn_status);
    
    // Jika len >= sizeof(header), berarti ada data yang terpotong
    if (len >= (int)sizeof(header)) {
        write_log("[ERROR] Headers too long, truncated!");
    }

    send(client_fd, header, len, 0);
}
/**********************************************************************
 * send_halmos_response()
 * ANALOGI :
 * Kurir pengantar paket yang bekerja 2 langkah:
 *
 * 1. Kirim dulu label paket (panggil send_http1_headers)
 * 2. Kalau surat ada isinya → kirim isinya
 *
 * Fungsi ini seperti kurir umum:
 * tidak peduli isi paket apa,
 * yang penting mengikuti aturan protokol pengiriman.
 **********************************************************************/
void send_halmos_response(int sock_client, HalmosResponse res, bool keep_alive) {
    // 1. Kirim dulu label paket/kop surat/amplop (panggil send_http1_headers)
    send_http1_headers(sock_client, &res, keep_alive);

    // 2. Kalau surat ada isinya → kirim isinya
    if (res.type == RES_TYPE_MEMORY && res.content != NULL && res.length > 0) {
        send(sock_client, res.content, res.length, 0);
    }
}

/**********************************************************************
 * send_mem_response()
 * ANALOGI :
 * Petugas cetak pesan cepat di loket informasi.
 *
 * Misal ada tamu bertanya:
 * → “Halaman tidak ada”
 *
 * Petugas langsung:
 * 1. Mengetik teks sederhana di kertas
 * 2. Memasukkannya ke format HalmosResponse
 * 3. Memanggil kurir (send_halmos_response)
 *
 * Cocok untuk:
 * - pesan sukses (200), error surat tidak ada 404
 * - pesan sederhana HTML
 * - balasan singkat tanpa file.
 **********************************************************************/
void send_mem_response(int client_fd, int status_code, const char *status_text, 
                       const char *content, bool keep_alive) {
    HalmosResponse res = {
        .type = RES_TYPE_MEMORY,
        .status_code = status_code,
        .status_message = status_text,
        .mime_type = "text/html",
        .content = (void*)content,
        .length = content ? strlen(content) : 0
    };
    
    send_halmos_response(client_fd, res, keep_alive);
}

/**********************************************************************
 * send_file_response()
 * ANALOGI :
 * Bagian GUDANG yang mengirim barang fisik.
 *
 * Alurnya seperti:
 * 1. Cari barang di rak (fopen)
 *    → kalau tidak ketemu, kirim surat “404”
 *
 * 2. Timbang barang dulu (hitung ukuran file)
 *
 * 3. Tempel label paket (send_http1_headers)
 *
 * 4. Kirim barang sedikit-sedikit pakai troli
 *    → dibaca per 8KB seperti kardus per kardus
 *
 * Fungsi ini khusus untuk:
 * - HTML statis
 * - gambar
 * - CSS/JS
 **********************************************************************/
void send_file_response(int client_fd, const char *file_path, const char *mime_type, bool keep_alive) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        write_log("ERROR", "File not found: %s", file_path);
        send_mem_response(client_fd, 404, "Not Found", "<h1>404 File Not Found</h1>", false);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Siapkan objek respon untuk file
    HalmosResponse res = {
        .type = RES_TYPE_FILE,
        .status_code = 200,
        .status_message = "OK",
        .mime_type = mime_type,
        .length = file_size
    };

    // Kirim Header dulu
    send_http1_headers(client_fd, &res, keep_alive);

    // Kirim isi file per bongkahan (chunk)
    char buffer[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        send(client_fd, buffer, bytes_read, 0);
    }

    fclose(file);
}