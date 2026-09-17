#ifndef HALMOS_HTTP2_MANAGER_H
#define HALMOS_HTTP2_MANAGER_H

#include "halmos_http2_core.h"
#include "halmos_core_conn_table.h"

/**
 * Main Loop untuk HTTP/2
 * Menggantikan http1_manager_session
 */


int http2_manager_session(halmos_conn_t *conn);
void http2_session_destroy(void *sess);

#endif