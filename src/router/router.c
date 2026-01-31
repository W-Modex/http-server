#include "router/router.h"
#include "http/response.h"
#include "router/handlers.h"
#include <stdlib.h>
#include <string.h>

const route_t ROUTES[] = {
    {HTTP_GET, "/", 0, static_get}, 
    {HTTP_GET, "/login", 0, static_get},
    {HTTP_POST, "/login", 0, post_login},
};

const size_t ROUTES_COUNT = sizeof(ROUTES)/sizeof(ROUTES[0]);

const route_t* router_find(http_method_t method, const char *path) {
    int idx = -1;
    for (int i = 0; i < ROUTES_COUNT; i++)
        if (ROUTES[i].method == method && strcmp(ROUTES[i].pattern, path) == 0)
            return ROUTES+i;
    return NULL;
}

int router_dispatch(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;
    const route_t* route = router_find(req->method, req->path);
    if (!route) return 0;
    return route->handler(req, res) ? 1 : -1;
}
