#include "auth/cookie.h"
#include "auth/crypto.h"
#include "auth/session.h"
#include "http/body.h"
#include "http/response.h"
#include <stdlib.h>

static int sid_cookie_stale(http_request_t *req) {
    if (!req || !req->jar) return 0;
    const char *sid_hex = cookie_jar_get(req->jar, SESSION_COOKIE_NAME);
    if (!sid_hex || !*sid_hex) return 0;
    return get_session(req) != 0;
}

static int clear_sid_cookie(http_response_t *res) {
    if (!res) return 0;
    cookie_settings_t opts = {0};
    opts.max_age = 0;
    opts.samesite = COOKIE_SAMESITE_LAX;
    opts.flags = (COOKIE_FLAG_HTTPONLY | COOKIE_FLAG_SECURE);
    opts.path = "/";

    char *cookie_value = build_set_cookie_value(SESSION_COOKIE_NAME, "", &opts);
    if (!cookie_value) return 0;

    int ok = http_response_add_header(res, "Set-Cookie", cookie_value) == 0;
    free(cookie_value);
    return ok;
}

int post_login(http_request_t* req, http_response_t* res) {
    if (http_request_parse_form(req) != 0) return 0;
    
    int stale_sid = sid_cookie_stale(req);

    if (get_user(req, res) == 0) {
        int ok = response_set_error(res, 400, "Bad Request");
        if (stale_sid && !clear_sid_cookie(res)) return 0;
        return ok;
    }

    if (create_session(req, res->user.id) == 0) {
        int ok = response_set_error(res, 500, "Internal Server Error");
        if (stale_sid && !clear_sid_cookie(res)) return 0;
        return ok;
    }

    cookie_settings_t opts = {0};
    opts.max_age = SESSION_TTL;
    opts.samesite = COOKIE_SAMESITE_LAX;
    opts.flags = (COOKIE_FLAG_HTTPONLY | COOKIE_FLAG_SECURE);
    opts.path = "/";

    char sid_hex[SESSION_ID_LEN * 2 + 1];
    if (hex_encode(req->session.sid, SESSION_ID_LEN, sid_hex, sizeof(sid_hex)) != 0)
        return response_set_error(res, 500, "Internal Server Error");

    char *cookie_value = build_set_cookie_value(SESSION_COOKIE_NAME, sid_hex, &opts);
    if (!cookie_value)
        return response_set_error(res, 500, "Internal Server Error");

    if (!response_set_redirect(res, 302, "/")) {
        free(cookie_value);
        return 0;
    }

    if (http_response_add_header(res, "Set-Cookie", cookie_value) != 0) {
        free(cookie_value);
        return 0;
    }
    free(cookie_value);

    return 1;
}

int post_signup(http_request_t* req, http_response_t* res) {
    if (http_request_parse_form(req) != 0) return 0;
    
    int stale_sid = sid_cookie_stale(req);

    if (create_user(req, res) == 0) {
        int ok = response_set_error(res, 500, "Internal Server Error");
        if (stale_sid && !clear_sid_cookie(res)) return 0;
        return ok;
    }

    if (create_session(req, res->user.id) == 0) {
        int ok = response_set_error(res, 500, "Internal Server Error");
        if (stale_sid && !clear_sid_cookie(res)) return 0;
        return ok;
    }

    cookie_settings_t opts = {0};
    opts.max_age = SESSION_TTL;
    opts.samesite = COOKIE_SAMESITE_LAX;
    opts.flags = (COOKIE_FLAG_HTTPONLY | COOKIE_FLAG_SECURE);
    opts.path = "/";

    char sid_hex[SESSION_ID_LEN * 2 + 1];
    if (hex_encode(req->session.sid, SESSION_ID_LEN, sid_hex, sizeof(sid_hex)) != 0)
        return response_set_error(res, 500, "Internal Server Error");

    char *cookie_value = build_set_cookie_value(SESSION_COOKIE_NAME, sid_hex, &opts);
    if (!cookie_value)
        return response_set_error(res, 500, "Internal Server Error");

    if (!response_set_redirect(res, 302, "/")) {
        free(cookie_value);
        return 0;
    }

    if (http_response_add_header(res, "Set-Cookie", cookie_value) != 0) {
        free(cookie_value);
        return 0;
    }
    free(cookie_value);

    return 1;
}
