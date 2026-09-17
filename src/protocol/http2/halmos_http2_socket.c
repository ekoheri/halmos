#include "halmos_http2_socket.h"
#include "halmos_sec_tls.h"
#include "halmos_log.h"

#include <unistd.h>             // Wajib untuk fungsi write() dan read() POSIX
#include <sys/types.h>
#include <stddef.h>


ssize_t http2_socket_write(int fd, bool is_tls, const void *buf, size_t len){
    if (is_tls) return ssl_send(fd, buf, len);
    return write(fd, buf, len);
}
 
ssize_t http2_socket_read(int fd, bool is_tls, void *buf, size_t len){
    if (is_tls) {
        SSL *ssl = ssl_get_for_fd(fd);
        if (!ssl) return -1;
        return (ssize_t)SSL_read(ssl, buf, (int)len);
    }
    return read(fd, buf, len);
}
 
void http2_socket_write_or_buffer(HTTP2Session *session, int fd, bool is_tls, const unsigned char *data, size_t len) {
    if (!session || len == 0) return;
 
    size_t already_sent = 0;
 
    if (session->pending_write_len <= session->pending_write_offset) {
        // Belum ada backlog - coba kirim langsung dulu.
        ssize_t n = http2_socket_write(fd, is_tls, data, len);
 
        if (n == (ssize_t)len) {
            return; // Terkirim penuh, tidak perlu buffer apa pun.
        }
 
        if (n < 0) {
            bool retry = false;
            // === PERBAIKAN: ssl_send() sekarang mengembalikan sentinel
            // SENDIRI (-EAGAIN/-EWOULDBLOCK untuk retry, -1 untuk error
            // fatal) - BUKAN nilai mentah dari SSL_write(). Memanggil
            // SSL_get_error(ssl, n) di sini SALAH: fungsi itu butuh return
            // value ASLI dari operasi SSL terakhir, bukan sentinel buatan
            // sendiri. Dulu ini bisa salah baca EAGAIN sebagai hard error
            // dan menutup koneksi HTTP/2 prematur di tengah transfer.
            if (is_tls) {
                if (n == -EAGAIN || n == -EWOULDBLOCK) retry = true;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                retry = true;
            }
 
            if (!retry) {
                write_log_error("[H2-SOCKET] Hard write error on FD %d, marking session failed", fd);
                session->write_error = true;
                return;
            }
            n = 0; // Belum ada satu byte pun yang terkirim
        }
 
        already_sent = (size_t)n;
    }
 
    size_t remaining = len - already_sent;
    if (remaining == 0) return;
 
    // Gabungkan sisa backlog lama (kalau ada) + sisa data baru yang belum terkirim.
    size_t old_unsent = session->pending_write_len - session->pending_write_offset;
    size_t new_total = old_unsent + remaining;
 
    unsigned char *new_buf = malloc(new_total);
    if (!new_buf) {
        write_log_error("[H2-SOCKET] Malloc failed for pending write buffer on FD %d", fd);
        session->write_error = true;
        return;
    }
 
    if (old_unsent > 0) {
        memcpy(new_buf, session->pending_write_buf + session->pending_write_offset, old_unsent);
    }
    memcpy(new_buf + old_unsent, data + already_sent, remaining);
 
    if (session->pending_write_buf) free(session->pending_write_buf);
    session->pending_write_buf = new_buf;
    session->pending_write_len = new_total;
    session->pending_write_offset = 0;
}

/**
 * Return: 0 = selesai penuh (buffer sudah dibebaskan), 1 = masih ada sisa
 * (EAGAIN, caller harus rearm & coba lagi nanti), -1 = hard error (caller
 * harus tutup koneksi).
 */
int http2_socket_flush_pending_write(HTTP2Session *session) {
    if (!session) return -1;
    if (session->pending_write_len <= session->pending_write_offset) return 0;
 
    size_t remaining = session->pending_write_len - session->pending_write_offset;
    ssize_t n = http2_socket_write(session->fd, session->is_tls,
                         session->pending_write_buf + session->pending_write_offset, remaining);
 
    if (n > 0) {
        session->pending_write_offset += (size_t)n;
        if (session->pending_write_offset >= session->pending_write_len) {
            free(session->pending_write_buf);
            session->pending_write_buf = NULL;
            session->pending_write_len = 0;
            session->pending_write_offset = 0;
            return 0;
        }
        return 1; // Masih ada sisa
    }
 
    if (n < 0) {
        bool retry = false;
        // === PERBAIKAN: sama seperti di http2_socket_write_or_buffer() - ssl_send()
        // sudah mengklasifikasi sendiri (-EAGAIN/-EWOULDBLOCK vs -1), tidak
        // perlu/boleh dipanggilkan SSL_get_error() lagi di atasnya.
        if (session->is_tls) {
            if (n == -EAGAIN || n == -EWOULDBLOCK) retry = true;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retry = true;
        }
        if (retry) return 1;
 
        write_log_error("[H2-SOCKET] Hard write error while flushing pending buffer on FD %d", session->fd);
        return -1;
    }
 
    return 1; // n == 0, jarang terjadi di socket non-blocking, anggap belum selesai
}
