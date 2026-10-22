#ifndef HALMOS_FCGI_FSM_H
#define HALMOS_FCGI_FSM_H

#include "halmos_fcgi_session.h" 

#include <stdint.h>
#include <stdbool.h>

// Fungsi utama yang dipanggil oleh worker untuk memproses task FSM
bool halmos_fcgi_fsm_step(HalmosFCGISession *session);

#endif // HALMOS_FCGI_FSM_H