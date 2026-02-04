#include "router/router.h"
#include "auth/session.h"
#include "http/request.h"
#include "http/response.h"
#include "router/handlers.h"
#include <stdlib.h>
#include <string.h>

const route_t ROUTES[] = {
    {HTTP_GET, "/", AUTH_REQUIRED, static_get}, 
    {HTTP_GET, "/chat", AUTH_REQUIRED, static_get}, 
    {HTTP_GET, "/about", AUTH_REQUIRED, static_get},
    {HTTP_GET, "/login", 0, static_get},
    {HTTP_POST, "/login", CSRF_REQUIRED, post_login},
    {HTTP_GET, "/signup", 0, static_get},
    {HTTP_POST, "/signup", CSRF_REQUIRED, post_signup},
    {HTTP_POST, "/logout", AUTH_REQUIRED, post_logout},
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
    if (!res) return 0;
    if (!req) return response_set_error(res, 400, "Bad Request");
    const route_t* route = router_find(req->method, req->path);
    if (!route) return 0;

    int ok = get_session(req);

    if ((route->flags & AUTH_REQUIRED) && !ok) 
        return response_set_redirect(res, 302, "/login");
    
    if (!(route->flags & AUTH_REQUIRED) && ok)
        return response_set_redirect(res, 302, "/");

    
    return route->handler(req, res) ? 1 : -1;
}
