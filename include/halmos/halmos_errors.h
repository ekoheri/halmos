#ifndef HALMOS_ERRORS_H
#define HALMOS_ERRORS_H

typedef enum {
    // ==========================================
    // KELOMPOK ERROR (Internal System, Kernel, & Admin Config)
    // ==========================================
    
    // --- 1. TRANSPORT (1000-1999) ---
    //transport/tcp_server.c
    ERR_TR_SOCKET_FLAGS     = 1000,
    ERR_TR_NONBLOCK         = 1001,
    ERR_TR_CREATE_MASTER    = 1002,
    ERR_TR_BIND             = 1003,
    ERR_TR_LISTEN           = 1004,

    // --- 2. CORE (2000-2999) ---
    //event_loop.c
    ERR_CORE_EPOLL_MEM      = 2000,
    ERR_CORE_EPOLL_CREATE   = 2001,
    ERR_CORE_EPOLL_ADD_SOCK = 2002,
    ERR_CORE_UDS_INIT       = 2003,
    ERR_CORE_EPOLL_WAIT     = 2004,
    ERR_CORE_ACCEPT_FAIL    = 2005,
    ERR_CORE_MAX_FD_EXCEED  = 2006,
    ERR_CORE_EPOLL_ADD_CLI  = 2007,
    ERR_CORE_EPOLL_REARM    = 2008,
    //conn_table.c
    ERR_CORE_INVALID_MAX_FD = 2009,
    ERR_CORE_SLOT_MEM       = 2010,
    ERR_CORE_IO_LOCK        = 2011,
    //queue.c
    ERR_CORE_INIT_WORKER    = 2012,
    ERR_CORE_QUEUE_CAPACITY = 2013,
    ERR_CORE_PTHREAD_SCALE  = 2014,
    //adaptive.c
    ERR_CORE_PHP_PATH_DEF   = 2015,
    ERR_CORE_PHP_OPEN_FAIL  = 2016,

    // --- 3. PROTOCOL / HTTP / WS / H2 (3000-3999) ---
    //protocol/bridge.c
    ERR_PROTO_DESTRUCTOR    = 3000,

    //protocol/http_utils.c
    ERR_PROTO_PATH_TOO_LONG = 3001,
    ERR_PROTO_REALPATH_FAIL = 3002,

    //protocol/http_route.c
    ERR_PROTO_ROUTE_FAIL    = 3003,
    ERR_PROTO_ROUTE_ACCESS  = 3004,

    //protocol/http_vhost.c
    ERR_PROTO_INOTIFY_INIT  = 3006,
    ERR_PROTO_INOTIFY_WATCH = 3007,
    ERR_PROTO_INOTIFY_EPOLL = 3008,

    //protocol/http_multipart.c
    ERR_PROTO_MULTIPART_MEM = 3009,
    
    //protocol/http1/http_manager.c
    ERR_PROTO_H1_FSM        = 3010,
    //protocol/http1/http_reponse.c
    ERR_PROTO_H1_DIR_OPEN   = 3011, // Gagal membuka direktori untuk listing
    ERR_PROTO_H1_FILE_SEEK  = 3012, // Gagal melakukan lseek pada file response
    ERR_PROTO_H1_FILE_READ  = 3013, // Gagal membaca file dari disk
    ERR_PROTO_H1_SOCKET_FAIL= 3014, // Kegagalan pengiriman socket/sendfile/TLS
    //protocol/websocket/ws_ipc.c
    ERR_PROTO_IPC_NOT_SOCK  = 3015,
    ERR_PROTO_IPC_CHMOD     = 3016,
    ERR_PROTO_IPC_LISTEN    = 3017,
    ERR_PROTO_IPC_NONBLOCK  = 3018,
    //protocol/websocket/ws_system.cs
    ERR_PROTO_WS_MAINT_TH   = 3019,
    //protocol/http2/http2_frame.c
    ERR_PROTO_H2_PARTIAL_W  = 3020,
    ERR_PROTO_H2_WIN_INC    = 3021,
    //protocol/http2/http2_socket.c
    ERR_PROTO_H2_HARD_W     = 3022,
    ERR_PROTO_H2_MALLOC     = 3023,
    ERR_PROTO_H2_FLUSH_W    = 3024,
    //protocol/http2/http2_router.c
    ERR_PROTO_H2_FCGI_ACQ   = 3025,
    //protocol/http2/http2_stream.c
    ERR_PROTO_H2_STREAM_MAL = 3026,
    //protocol/http2/http2_parser.c
    ERR_PROTO_H2_REALLOC    = 3027,
    //protocol/http2/http2_manager.c
    ERR_PROTO_H2_PAYLOAD_L  = 3028,

    // --- 4. SECURITY (4000-4999) ---
    //security/traffic.c
    ERR_SEC_JANITOR_TH      = 4000,
    //security/ssl.c
    ERR_SEC_SSL_CTX         = 4001,
    ERR_SEC_LOAD_CERT       = 4002,
    ERR_SEC_LOAD_KEY        = 4003,
    ERR_SEC_SLOT_MAP        = 4004,

    // --- 5. FASTCGI (5000-5999) ---
    //fastcgi/fcgi_session.c
    ERR_FCGI_NO_NODES       = 5000,
    ERR_FCGI_FETCH_POOL     = 5001,
    //fastcgi/fcgi_pool.c
    ERR_FCGI_MEM_ALLOC      = 5002,
    //fastcgi/fcgi_proto.c
    ERR_FCGI_RCV_TIMEO      = 5003,
    ERR_FCGI_TIMEOUT        = 5004,
    ERR_FCGI_CONN_LOST      = 5005,
    ERR_FCGI_DESYNC         = 5006,
    ERR_FCGI_PHP_STDERR     = 5007,

    // ==========================================
    // KELOMPOK WARNING (Murni Perilaku / Aksi User)
    // ==========================================
    //protocol/http_utils.c
    WARN_PROTO_PATH_TRAVERSAL = 9000,
    //protocol/http1/http_parser.c
    WARN_PROTO_H1_MALFORMED   = 9001,
    //protocol/http_multipart.c
    WARN_PROTO_MULTIPART_BND  = 9002,
    //protocol/websocket/ws_system.cs
    WARN_PROTO_WS_FIN_0       = 9003,
    WARN_PROTO_WS_CTRL_LEN    = 9004,
    WARN_PROTO_WS_UNMASKED    = 9005,
    WARN_PROTO_WS_PAYLOAD_SZ  = 9006,
    WARN_PROTO_WS_JSON_ERR    = 9007,
    WARN_PROTO_WS_IPC_JSON    = 9008, 
    //security/traffic.c
    WARN_SEC_RATE_LIMIT       = 9500

} HalmosErrorCode;

const char* get_error_template(HalmosErrorCode code);
const char* get_module_prefix(HalmosErrorCode code);

#endif