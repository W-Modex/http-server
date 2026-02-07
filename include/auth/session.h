#ifndef SESSION_H
#define SESSION_H

#include "http/request.h"
#include "http/response.h"

#define SESSION_ID_LEN (sizeof(((session_t *)0)->sid))
#define SESSION_CSRF_LEN (sizeof(((session_t *)0)->csrf_secret))
#define SESSION_COOKIE_NAME "sid"
#define SESSION_CREATE_MAX_ATTEMPTS 8
#define SESSION_TTL (7 * 24 * 60 * 60 * 1000)
#define SESSION_INACTIVITY_TTL (30 * 60 * 1000)

extern u_store_t* user_store;

int create_session(http_request_t* req, uint64_t uid);
int create_anonymous_session(http_request_t* req);
int set_session_cookie(http_response_t* res, const session_t* session, long max_age);
int destroy_session(unsigned char* sid);
int get_session(http_request_t* req);
int rotate_session(http_request_t* req);
int session_is_authenticated(const session_t* session);

int create_user(http_request_t* req, http_response_t* res);
int get_user(http_request_t* req, http_response_t* res);
user_t* get_user_by_email(const char* email);
user_t* get_user_by_username(const char* username);

#endif
