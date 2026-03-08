#ifndef HALMOS_HTTP_VHOST_H
#define HALMOS_HTTP_VHOST_H

#include "halmos_core_config.h"
#include <time.h>

/* --- Prototipe Fungsi --- */

/**
 * Mencari pointer ke struktur VHost berdasarkan header Host dari client.
 * Ini lebih baik daripada hanya mengembalikan string root, 
 * karena kita butuh akses ke tabel rutenya juga.
 */
VHostEntry* http_vhost_get_context(const char *incoming_host);

/**
 * Melakukan inisialisasi awal (jika diperlukan) 
 * atau sinkronisasi daftar VHost dari config global.
 */
void http_vhost_init_all();

/**
 * Menjalankan auto-reload .htroute untuk SETIAP Virtual Host.
 * Fungsi ini dipanggil secara periodik di event loop utama.
 */
void http_vhost_reload_routes();

#endif