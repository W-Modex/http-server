#ifndef HANDLERS_H
#define HANDLERS_H

#include "http/response.h"

int post_login(http_request_t* req, http_response_t* res);
int post_signup(http_request_t* req, http_response_t* res);
int post_logout(http_request_t* req, http_response_t* res);
int google_oauth_start(http_request_t* req, http_response_t* res);
int google_oauth_callback(http_request_t* req, http_response_t* res);

#endif