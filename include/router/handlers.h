#ifndef HANDLERS_H
#define HANDLERS_H

#include "http/response.h"

int get_home(http_request_t* req, http_response_t* res);
int get_login(http_request_t* req, http_response_t* res);
int post_login(http_request_t* req, http_response_t* res);

#endif