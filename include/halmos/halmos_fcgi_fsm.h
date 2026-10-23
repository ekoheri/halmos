#ifndef HALMOS_FCGI_FSM_H
#define HALMOS_FCGI_FSM_H

#include "halmos_fcgi_session.h" 

#include <stdint.h>
#include <stdbool.h>

bool fcgi_fsm_step(FCGI_Session *session);

#endif // HALMOS_FCGI_FSM_H