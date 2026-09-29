#ifndef HALMOS_HTTP2_ROUTER_H
#define HALMOS_HTTP2_ROUTER_H

#include "halmos_http2_core.h"

/**
 Bertugas menentukan ke mana request harus diarahkan 
 setelah stream dan header-nya lengkap terkumpul 
 (apakah ke FastCGI, file statis, atau WebSocket).
 */

void http2_router_bridge(HTTP2Session *session, HTTP2Stream *stream);

#endif /* HALMOS_HTTP2_ROUTER_H */