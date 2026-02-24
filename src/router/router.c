#include "router/router.h"
#include "auth/csrf.h"
#include "auth/cookie.h"
#include "auth/session.h"
#include "http/request.h"
#include "http/response.h"
#include "router/handlers.h"
#include <stdlib.h>
#include <string.h>

static int html_route_alias_match(const char *pattern, const char *path) {
    if (!pattern || !path) return 0;
    if (strcmp(pattern, path) == 0) return 1;

    if (strcmp(pattern, "/") == 0) {
        return strcmp(path, "/index.html") == 0;
    }

    size_t plen = strlen(pattern);
    size_t path_len = strlen(path);
    if (plen == 0) return 0;

    if (path_len == plen + 1 &&
        strncmp(path, pattern, plen) == 0 &&
        path[plen] == '/') {
        return 1;
    }

    static const char suffix[] = "/index.html";
    size_t suffix_len = sizeof(suffix) - 1;
    if (path_len == plen + suffix_len &&
        strncmp(path, pattern, plen) == 0 &&
        strcmp(path + plen, suffix) == 0) {
        return 1;
    }

    return 0;
}

const route_t ROUTES[] = {
    {HTTP_GET, "/", ENSURE_SESSION | RENDER_HTML, static_get},
    {HTTP_GET, "/docs", AUTH_REQUIRED | RENDER_HTML, static_get},
    {HTTP_GET, "/security", AUTH_REQUIRED | RENDER_HTML, static_get},
    {HTTP_GET, "/about", AUTH_REQUIRED | RENDER_HTML, static_get},
    {HTTP_GET, "/login", ANON_ONLY | ENSURE_SESSION | RENDER_HTML, static_get},
    {HTTP_POST, "/login", ANON_ONLY | CSRF_REQUIRED, post_login},
    {HTTP_GET, "/signup", ANON_ONLY | ENSURE_SESSION | RENDER_HTML, static_get},
    {HTTP_POST, "/signup", ANON_ONLY | CSRF_REQUIRED, post_signup},
    {HTTP_POST, "/logout", AUTH_REQUIRED | CSRF_REQUIRED, post_logout},
    {HTTP_GET, "/oauth/google/start", ANON_ONLY | ENSURE_SESSION, google_oauth_start},
    {HTTP_GET, "/oauth/google/callback", ANON_ONLY | ENSURE_SESSION, google_oauth_callback},
};

const size_t ROUTES_COUNT = sizeof(ROUTES)/sizeof(ROUTES[0]);

const route_t* router_find(http_method_t method, const char *path) {
    if (!path) return NULL;
    for (size_t i = 0; i < ROUTES_COUNT; i++) {
        if (ROUTES[i].method != method) continue;
        if (strcmp(ROUTES[i].pattern, path) == 0)
            return &ROUTES[i];
        if (method == HTTP_GET &&
            (ROUTES[i].flags & RENDER_HTML) &&
            html_route_alias_match(ROUTES[i].pattern, path)) {
            return &ROUTES[i];
        }
    }
    return NULL;
}

int router_dispatch(http_request_t *req, http_response_t *res) {
    if (!res) return 0;
    if (!req) return response_set_error(res, 400, "Bad Request");
    const route_t* route = router_find(req->method, req->path);
    if (!route) return 0;

    int has_session = get_session(req);
    int is_auth = session_is_authenticated(&req->session);

    if ((route->flags & AUTH_REQUIRED) && !is_auth) 
        return response_set_redirect(res, 302, "/login");
    
    if ((route->flags & ANON_ONLY) && is_auth)
        return response_set_redirect(res, 302, "/");

    int issued_session = 0;
    if ((route->flags & ENSURE_SESSION) && !has_session) {
        if (!create_anonymous_session(req))
            return response_set_error(res, 500, "Internal Server Error");
        issued_session = 1;
    }

    if ((route->flags & CSRF_REQUIRED) &&
        (req->method == HTTP_POST || req->method == HTTP_PUT ||
         req->method == HTTP_PATCH || req->method == HTTP_DELETE)) {
        if (!csrf_validate_request(req))
            return response_set_error(res, 403, "Forbidden");
    }

    int handled = route->handler(req, res) ? 1 : -1;
    if (handled > 0) {
        if (issued_session) {
            if (!set_session_cookie(res, &req->session, COOKIE_MAX_AGE_UNSET))
                return -1;
        }
        if (route->flags & RENDER_HTML) {
            if (!render_html(req, res))
                return -1;
        }
        if (!csrf_maybe_inject(req, res))
            return -1;
    }
    return handled;
}
