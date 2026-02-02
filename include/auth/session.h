#ifndef SESSION_H
#define SESSION_H

#include "http/request.h"

#define SESSION_ID_LEN (sizeof(((session_t *)0)->sid))
#define SESSION_CSRF_LEN (sizeof(((session_t *)0)->csrf_secret))
#define SESSION_COOKIE_NAME "sid"
#define SESSION_CREATE_MAX_ATTEMPTS 8
#define SESSION_TTL (7 * 24 * 60 * 60 * 1000)

session_t create_session(uint64_t uid);
int destroy_session(unsigned char* sid);
int get_session(http_request_t* req);
int rotate_session(http_request_t* req);

#endif
