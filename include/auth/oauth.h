#ifndef OAUTH_H
#define OAUTH_H

#include "http/request.h"
#include "http/response.h"



int oauth_start(http_request_t* req, http_response_t* res);
int oauth_callback(http_request_t* req, http_response_t* res);

#endif