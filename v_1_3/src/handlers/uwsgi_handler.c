#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "uwsgi_handler.h"

#define UWSGI_BUFFER_SIZE 16384

/**********************************************************************
 * add_uwsgi_pair()
 * ANALOGI FUNGSI :
 *
 * add_uwsgi_pair = seperti MENULIS SATU BARIS FORMULIR
 * untuk dimasukkan ke dalam amplop uWSGI.
 *
 * Di protokol uWSGI, setiap data dikirim dalam bentuk:
 *
 * [panjang_nama 2 byte][nama][panjang_value 2 byte][value]
 *
 * Mirip formulir:
 *   Nama Kolom  : REQUEST_METHOD
 *   Isinya      : POST
 *
 * Fungsi ini tugasnya:
 * - menulis nama variabel
 * - menulis isinya
 * - dalam format Little Endian
 **********************************************************************/
static int add_uwsgi_pair(unsigned char* dest, const char *name, const char *value) {
    uint16_t nlen = (uint16_t)strlen(name);
    uint16_t vlen = (uint16_t)(value ? strlen(value) : 0);

    uint16_t nlen_le = nlen; // Little Endian (x86 default)
    uint16_t vlen_le = vlen;

    int offset = 0;
    memcpy(dest + offset, &nlen_le, 2); offset += 2;
    memcpy(dest + offset, name, nlen);   offset += nlen;
    memcpy(dest + offset, &vlen_le, 2); offset += 2;
    memcpy(dest + offset, value ? value : "", vlen); offset += vlen;

    return offset;
}

/**********************************************************************
 * uwsgi_request_stream()
 * ANALOGI BESAR :
 *
 * Fungsi uwsgi_request_stream adalah seperti:
 *
 * "Kurir Halmos yang mengantar request HTTP
 *  ke kantor backend uWSGI (Python/Django/Flask),
 *  lalu membawa pulang hasilnya."
 *
 * Tahap kerjanya:
 * 1. Menelpon kantor backend (connect socket)
 * 2. Menulis formulir uWSGI (params)
 * 3. Mengirim isi POST jika ada
 * 4. Menunggu balasan
 * 5. Memisahkan header & body
 **********************************************************************/
UWSGI_Response uwsgi_request_stream(
    const char *target_ip, int target_port, int sock_client,
    const char *method, const char *script_name, const char *query_string,
    void *post_data, size_t post_data_len, size_t content_length, const char *content_type) {

    /**************************************************************
     * 1. Membuka koneksi ke WSGI Python
     * ANALOGI :
     * Kurir mencari alamat kantor backend
     * lalu mencoba mengetuk pintu (connect).
     **************************************************************/
    UWSGI_Response res = {NULL, NULL, 0};
    int u_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(u_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(u_sock);
        return res;
    }

    /**************************************************************
     *  2. BUAT PACKET PARAMS
     * ANALOGI :
     * Menulis FORMULIR yang akan dimasukkan ke amplop uWSGI.
     *
     * Isinya seperti:
     * - REQUEST_METHOD = GET/POST
     * - PATH_INFO      = /index.py
     * - QUERY_STRING   = id=10
     **************************************************************/
    unsigned char params_buf[UWSGI_BUFFER_SIZE];
    int p_pos = 4; // Sisakan 4 byte untuk uwsgi_packet_header

    p_pos += add_uwsgi_pair(params_buf + p_pos, "REQUEST_METHOD", method);
    p_pos += add_uwsgi_pair(params_buf + p_pos, "PATH_INFO", script_name);
    p_pos += add_uwsgi_pair(params_buf + p_pos, "QUERY_STRING", query_string ? query_string : "");
    p_pos += add_uwsgi_pair(params_buf + p_pos, "SERVER_PROTOCOL", "HTTP/1.1");
    
    if (content_length > 0) {
        char cl_str[20];
        snprintf(cl_str, sizeof(cl_str), "%zu", content_length);
        p_pos += add_uwsgi_pair(params_buf + p_pos, "CONTENT_LENGTH", cl_str);
        p_pos += add_uwsgi_pair(params_buf + p_pos, "CONTENT_TYPE", content_type ? content_type : "");
    }

    /**************************************************************
     * 3. ISI HEADER UWSGI (4 Byte)
     * ANALOGI :
     * Menutup amplop dengan HEADER uWSGI.
     *
     * 4 byte pertama adalah:
     * [modifier1][ukuran][ukuran][modifier2]
     *
     * Seperti cap resmi dari kantor pos uWSGI.
     **************************************************************/
    uint16_t pktsize = p_pos - 4;
    params_buf[0] = 0; // modifier1: 0 (Python WSGI)
    params_buf[1] = pktsize & 0xff;
    params_buf[2] = (pktsize >> 8) & 0xff;
    params_buf[3] = 0; // modifier2: 0

    /**************************************************************
     * 4. KIRIM PARAMS
     * ANALOGI :
     * Kurir menyerahkan formulir ke resepsionis backend.
     **************************************************************/
    send(u_sock, params_buf, p_pos, 0);

    /**************************************************************
     * 5. STREAMING BODY (POST DATA)
     * ANALOGI :
     *
     * Kalau ada lampiran (POST data),
     * kurir mengirimnya bertahap:
     *
     * 1. Kirim yang sudah dibaca parser
     * 2. Kalau masih kurang,
     *    ambil langsung dari klien asli
     **************************************************************/
    size_t total_sent = 0;
    // Kirim sisa yang sudah ada di buffer parser
    if (post_data_len > 0) {
        send(u_sock, post_data, post_data_len, 0);
        total_sent += post_data_len;
    }

    // Tarik langsung dari socket client jika masih ada sisa
    if (total_sent < content_length) {
        char stream_buf[8192];
        while (total_sent < content_length) {
            ssize_t n = recv(sock_client, stream_buf, sizeof(stream_buf), 0);
            if (n <= 0) break;
            send(u_sock, stream_buf, n, 0);
            total_sent += n;
        }
    }

    /**************************************************************
     * 6. TERIMA RESPONSE (RAW HTTP STREAM)
     * ANALOGI:
     *
     * Backend tidak pakai paket END seperti FastCGI.
     * Jadi kurir menunggu sampai:
     *
     * pihak backend MENUTUP PINTU
     * itulah tanda balasan selesai.
     * Berbeda dengan FastCGI, uWSGI tidak punya "End Request" packet. 
     * Kita baca sampai socket ditutup oleh backend.
     **************************************************************/
    char *raw_res = NULL;
    size_t raw_len = 0;
    char recv_buf[8192];
    ssize_t n;
    while ((n = recv(u_sock, recv_buf, sizeof(recv_buf), 0)) > 0) {
        char *tmp = realloc(raw_res, raw_len + n + 1);
        if (tmp) {
            raw_res = tmp;
            memcpy(raw_res + raw_len, recv_buf, n);
            raw_len += n;
            raw_res[raw_len] = '\0';
        }
    }

    /**************************************************************
     * // 6. PARSING HEADER & BODY
     * ANALOGI :
     *
     * Setelah dapat surat balasan mentah dari backend Python:
     *
     * Kurir memisahkan:
     * - amplop depan = header HTTP
     * - isi surat    = body
     **************************************************************/
    if (raw_res) {
        char *delim = strstr(raw_res, "\r\n\r\n");
        if (delim) {
            *delim = '\0';
            res.header = strdup(raw_res);
            res.body_len = raw_len - (delim + 4 - raw_res);
            res.body = malloc(res.body_len + 1);
            memcpy(res.body, delim + 4, res.body_len);
            res.body[res.body_len] = '\0';
        } else {
            res.body = strdup(raw_res);
            res.body_len = raw_len;
        }
        free(raw_res);
    }

    close(u_sock);
    return res;
}

/**********************************************************************
 * free_uwsgi_response()
 * ANALOGI :
 *
 * Setelah surat dibaca,
 * kertas bekas harus dibuang agar meja tidak penuh.
 *
 * Fungsi ini = petugas kebersihan memori.
 **********************************************************************/
void free_uwsgi_response(UWSGI_Response *res) {
    if (res->header) free(res->header);
    if (res->body) free(res->body);
}