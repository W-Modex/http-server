#ifndef ROUTER_H
#define ROUTER_H

#include "http/request.h"
#include "http/response.h"


typedef int (*handler_fn)(http_request_t *req, http_response_t* res);

typedef struct {
    http_method_t method;
    const char *pattern; 
    unsigned flags;
    handler_fn handler;
} route_t;

const route_t* router_find(http_method_t method, const char* path);
int router_dispatch(http_request_t* req, http_response_t* res);

#endif
