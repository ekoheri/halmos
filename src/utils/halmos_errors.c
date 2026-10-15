#include "halmos_errors.h"
#include <stddef.h>

typedef struct {
    HalmosErrorCode code;
    const char *template_str;
} ErrorMapping;

static const ErrorMapping ERROR_TABLE[] = {
    // --- ERROR ---
    //transport/tcp_server.c
    { ERR_TR_SOCKET_FLAGS,     "Failed to get socket flags for FD %d" },
    { ERR_TR_NONBLOCK,         "Failed to set O_NONBLOCK for FD %d" },
    { ERR_TR_CREATE_MASTER,    "Failed to create master socket: %s" },
    { ERR_TR_BIND,             "Bind failed on %s:%d. Address already in use?" },
    { ERR_TR_LISTEN,           "Listen failed on %s:%d: %s" },

    //core/event_loop.c
    { ERR_CORE_EPOLL_MEM,      "Failed to allocate memory for epoll events" },
    { ERR_CORE_EPOLL_CREATE,   "epoll_create1 failed: %s" },
    { ERR_CORE_EPOLL_ADD_SOCK, "Failed to add sock_server to epoll: %s" },
    { ERR_CORE_UDS_INIT,       "IPC UDS Bridge initialization failed" },
    { ERR_CORE_EPOLL_WAIT,     "epoll_wait critical error: %s" },
    { ERR_CORE_ACCEPT_FAIL,    "Accept failed: %s (Errno: %d)" },
    { ERR_CORE_MAX_FD_EXCEED,  "FD %d exceeds g_max_fd capacity limit" },
    { ERR_CORE_EPOLL_ADD_CLI,  "Epoll add failed for client FD %d: %s" },
    { ERR_CORE_EPOLL_REARM,    "Failed to re-arm epoll for FD %d: %s" },
    //core/conn_table.c
    { ERR_CORE_INVALID_MAX_FD, "Invalid g_max_fd (0) for connection system initialization" },
    { ERR_CORE_SLOT_MEM,       "Out of memory allocating %u connection slots" },
    { ERR_CORE_IO_LOCK,        "Failed to init io_lock for FD slot %u" },
    //core/queue.c
    { ERR_CORE_INIT_WORKER,    "Failed to create initial worker thread %d" },
    { ERR_CORE_QUEUE_CAPACITY, "Capacity reached! Rejecting client FD %d (Gen: %u)" },
    { ERR_CORE_PTHREAD_SCALE,  "pthread_create failed while upscaling worker threads" },
    //core/adaptive.c
    { ERR_CORE_PHP_PATH_DEF,   "PHP-FPM config path not defined, using baseline default (max_children=50)" },
    { ERR_CORE_PHP_OPEN_FAIL,  "Failed to open PHP-FPM config: %s. Fallback to max_children=50" },

    //protocol/bridge.c
    { ERR_PROTO_DESTRUCTOR,    "Unknown protocol_session destructor on FD %d, closing session" },
    //protocol/http_utils.c
    { ERR_PROTO_PATH_TOO_LONG, "URL path is too long" },
    { ERR_PROTO_REALPATH_FAIL, "Realpath failed for: %s. Reason: %s" },
    //protocol/http_route.c
    { ERR_PROTO_ROUTE_FAIL,    "System error on routing path [%s]: %s (errno: %d)" },
    { ERR_PROTO_ROUTE_ACCESS,  "Cannot access routing configuration file: %s" },
    //protocol/http_vhost.c
    { ERR_PROTO_INOTIFY_INIT,  "Failed to initialize inotify watcher: %s" },
    { ERR_PROTO_INOTIFY_WATCH, "Failed to add watch for path %s: %s" },
    { ERR_PROTO_INOTIFY_EPOLL, "Failed to add vhost inotify descriptor to epoll: %s" },
    //protocol/http_multipart.c
    { ERR_PROTO_MULTIPART_MEM, "Failed to reallocate multipart parts memory for IP: %s" },
    //protocol/http1/http_manager.c
    { ERR_PROTO_H1_FSM,         "Failed to create FastCGI FSM session (Out of memory or resource limit reached)" },
    //protocol/http1/http_reponse.c
    { ERR_PROTO_H1_DIR_OPEN,    "Failed to open directory path for listing: %s. Access denied or not found" },
    { ERR_PROTO_H1_FILE_SEEK,   "Failed to execute lseek on response file descriptor: %s (errno: %d)" },
    { ERR_PROTO_H1_FILE_READ,   "Failed to read file chunk from disk during response transmission: %s (errno: %d)" },
    { ERR_PROTO_H1_SOCKET_FAIL, "Fatal transmission error on client socket FD %d: %s (errno: %d)" },
    //protocol/websocket/ws_ipc.c
    { ERR_PROTO_IPC_NOT_SOCK,  "IPC file %s exists and is NOT a socket. Aborting" },
    { ERR_PROTO_IPC_CHMOD,     "Failed to change file permissions on IPC path: %s" },
    { ERR_PROTO_IPC_LISTEN,    "IPC Listen failed on path %s: %s" },
    { ERR_PROTO_IPC_NONBLOCK,  "Failed to set non-blocking flag on bridge_fd" },
    //protocol/websocket/ws_system.cs
    { ERR_PROTO_WS_MAINT_TH,   "Failed to start WebSocket maintenance background thread" },
    //protocol/http2/http2_frame.c
    { ERR_PROTO_H2_PARTIAL_W,  "HTTP/2 Partial write (no session context) on frame type 0x%02X" },
    { ERR_PROTO_H2_WIN_INC,    "HTTP/2 Window update error: Increment of 0 on stream ID %u" },
    //protocol/http2/http2_socket.c
    { ERR_PROTO_H2_HARD_W,     "HTTP/2 Hard write error on FD %d, marking session as failed" },
    { ERR_PROTO_H2_MALLOC,     "HTTP/2 Malloc failed for pending write buffer on FD %d" },
    { ERR_PROTO_H2_FLUSH_W,    "HTTP/2 Hard write error while flushing pending buffer on FD %d" },
    //protocol/http2/http2_router.c
    { ERR_PROTO_H2_FCGI_ACQ,   "HTTP/2 Failed to acquire FPM connection / No backend nodes configured for URI: %s" },
    //protocol/http2/http2_stream.c
    { ERR_PROTO_H2_STREAM_MAL, "HTTP/2 Malloc failed for new stream ID %u" },
    //protocol/http2/http2_parser.c
    { ERR_PROTO_H2_REALLOC,    "HTTP/2 Realloc failed for stream ID %d" },
    //protocol/http2/http2_manager.c
    { ERR_PROTO_H2_PAYLOAD_L,  "HTTP/2 Frame payload length %u exceeds limit (%zu bytes) on FD %d" },
    //security/traffic.c
    { ERR_SEC_JANITOR_TH,      "Failed to start security Janitor background thread" },
    //security/ssl.c
    { ERR_SEC_SSL_CTX,         "Failed to create SSL context: %s" },
    { ERR_SEC_LOAD_CERT,       "Failed to load TLS certificate file: %s" },
    { ERR_SEC_LOAD_KEY,        "Failed to load TLS private key file: %s" },
    { ERR_SEC_SLOT_MAP,        "Security mapping failed: FD %d has no active connection slot" },
    //fastcgi/fcgi_session.c
    { ERR_FCGI_NO_NODES,       "No backend nodes configured for FastCGI backend type %d" },
    { ERR_FCGI_FETCH_POOL,     "Failed to acquire connection from FPM pool for URI: %s"},
    //fastcgi/fcgi_pool.c
    { ERR_FCGI_MEM_ALLOC,      "FastCGI Pool fatal: Memory allocation failed" },
    //fastcgi/fcgi_proto.c
    { ERR_FCGI_RCV_TIMEO,      "FastCGI socket setsockopt SO_RCVTIMEO failed: %s" },
    { ERR_FCGI_TIMEOUT,        "FastCGI timeout: Backend unresponsive for 30s at URI: %s" },
    { ERR_FCGI_CONN_LOST,      "FastCGI connection lost or header malformed" },
    { ERR_FCGI_DESYNC,         "FastCGI protocol desync or timeout. Closing backend socket connection" },
    { ERR_FCGI_PHP_STDERR,     "PHP-FPM stderr message: %s" },

    // --- WARNING ---
    //protocol/http_utils.c
    { WARN_PROTO_PATH_TRAVERSAL,"Path traversal security attempt blocked: %s" },
    //protocol/http1/http_parser.c 
    { WARN_PROTO_H1_MALFORMED, "Malformed HTTP request header: missing end delimiter or invalid structure from client" },
    //protocol/http_multipart.c
    { WARN_PROTO_MULTIPART_BND, "Multipart boundary missing from client request IP: %s" },
    //protocol/websocket/ws_system.cs
    { WARN_PROTO_WS_FIN_0,     "WebSocket FD %d: Fragmentation intentionally unsupported (FIN=0). Dropping frame." },
    { WARN_PROTO_WS_CTRL_LEN,  "WebSocket FD %d: Control frame exceeds 125 bytes limit (%zu bytes)" },
    { WARN_PROTO_WS_UNMASKED,  "WebSocket FD %d: Client-to-server frame unmasked protocol violation" },
    { WARN_PROTO_WS_PAYLOAD_SZ,"WebSocket FD %d payload size limit exceeded (%zu bytes)" },
    { WARN_PROTO_WS_JSON_ERR,  "Malformed JSON payload on WebSocket FD %d (Stream ID %u)" },
    { WARN_PROTO_WS_IPC_JSON,  "Malformed internal JSON received in WebSocket IPC" },
    //security/traffic.c
    { WARN_SEC_RATE_LIMIT,     "Rate limit exceeded for client IP: %s (Limit: %d req/sec)" }
};

const char* get_module_prefix(HalmosErrorCode code) {
    if (code >= 1000 && code < 2000) return "TRANSPORT";
    if (code >= 2000 && code < 3000) return "CORE";
    if (code >= 3000 && code < 4000) return "PROTOCOL";
    if (code >= 4000 && code < 5000) return "SECURITY";
    if (code >= 5000 && code < 6000) return "FASTCGI";
    if (code >= 9000 && code <= 9999) return "WARNING";
    return "UNKNOWN";
}

const char* get_error_template(HalmosErrorCode code) {
    size_t table_size = sizeof(ERROR_TABLE) / sizeof(ERROR_TABLE[0]);
    for (size_t i = 0; i < table_size; i++) {
        if (ERROR_TABLE[i].code == code) {
            return ERROR_TABLE[i].template_str;
        }
    }
    return "Unknown system error occurred";
}