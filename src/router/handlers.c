#include "auth/cookie.h"
#include "auth/crypto.h"
#include "auth/oauth.h"
#include "auth/session.h"
#include "http/body.h"
#include "http/response.h"
#include <stdlib.h>
#include <time.h>

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

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

    if (!response_set_redirect(res, 302, "/")) {
        return 0;
    }
    if (!set_session_cookie(res, &req->session, SESSION_TTL)) {
        return 0;
    }

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

    if (!response_set_redirect(res, 302, "/")) {
        return 0;
    }
    
    if (!set_session_cookie(res, &req->session, SESSION_TTL)) {
        return 0;
    }

    return 1;
}

int post_logout(http_request_t* req, http_response_t* res) {
    if (!req || !res) return 0;

    int has_session = req->session.created_at != 0;
    if (!has_session) {
        has_session = get_session(req) != 0;
    }

    if (has_session && destroy_session(req->session.sid) == 0)
        return response_set_error(res, 500, "Internal Server Error");

    if (!response_set_redirect(res, 302, "/login"))
        return 0;

    if (clear_sid_cookie(res) == 0)
        return response_set_error(res, 500, "Internal Server Error");

    return 1;
}

int google_oauth_start(http_request_t* req, http_response_t* res) {
    if (!req || !res) return 0;

    const oauth_provider_t* p = get_oauth_provider("Google");
    if (!p)
        return response_set_error(res, 404, "Not Found");

    int ok = 0;
    char *state = NULL;
    char *nonce = NULL;
    char *verifier = NULL;
    char *challenge = NULL;
    char *authorize_url = NULL;

    if (random_base64url(48, &state) != 0) goto cleanup;
    if (random_base64url(48, &nonce) != 0) goto cleanup;
    if (random_base64url(72, &verifier) != 0) goto cleanup;
    if (!oauth_pkce_challenge(verifier, &challenge)) goto cleanup;

    int64_t created_at = now_ms();
    if (created_at == 0) created_at = (int64_t)time(NULL) * 1000;

    oauth_flow_t flow = {0};
    str_copy(flow.state, state, sizeof(flow.state));
    str_copy(flow.nonce, nonce, sizeof(flow.nonce));
    str_copy(flow.code_verifier, verifier, sizeof(flow.code_verifier));
    flow.provider = p;
    flow.created_at_ms = created_at;
    flow.expires_at_ms = created_at + OAUTH_FLOW_TTL_MS;

    if (!oauth_build_authorize_url(p, state, nonce, challenge, &authorize_url)) goto cleanup;
    if (!oauth_flow_store_put(&oauth_flows, &flow)) goto cleanup;

    if (!response_set_redirect(res, 302, authorize_url)) {
        oauth_flow_t unused = {0};
        oauth_flow_store_get(&oauth_flows, state, &unused);
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (!ok) ok = response_set_error(res, 500, "Internal Server Error");
    free(state);
    free(nonce);
    free(verifier);
    free(challenge);
    free(authorize_url);
    return ok;
}

int google_oauth_callback(http_request_t* req, http_response_t* res) {
    if (!req || !res) return 0;

    const char *oauth_error = get_request_params(req, "error");
    if (oauth_error && *oauth_error) {
        return response_set_redirect(res, 302, "/login");
    }

    const char *state = get_request_params(req, "state");
    const char *code = get_request_params(req, "code");
    if (!state || !*state || !code || !*code) {
        return response_set_error(res, 400, "Bad Request");
    }

    oauth_flow_t flow = {0};
    if (!oauth_flow_store_get(&oauth_flows, state, &flow)) {
        return response_set_error(res, 400, "Bad Request");
    }

    char *id_token = NULL;
    char *email = NULL;
    char *username_seed = NULL;
    int ok = 0;

    if (!oauth_exchange_code_for_id_token(&flow, code, &id_token)) {
        ok = response_set_redirect(res, 302, "/login");
        goto cleanup;
    }

    if (!oauth_extract_google_identity_from_id_token(&flow, id_token, &email, &username_seed)) {
        ok = response_set_redirect(res, 302, "/login");
        goto cleanup;
    }
    
    uint64_t uid = oauth_find_or_create_user(email, username_seed);
    if (uid == 0) {
        ok = response_set_error(res, 500, "Internal Server Error");
        goto cleanup;
    }

    if (create_session(req, uid) == 0) {
        ok = response_set_error(res, 500, "Internal Server Error");
        goto cleanup;
    }
    if (!response_set_redirect(res, 302, "/")) {
        ok = 0;
        goto cleanup;
    }
    if (!set_session_cookie(res, &req->session, SESSION_TTL)) {
        ok = 0;
        goto cleanup;
    }
    ok = 1;

cleanup:
    free(id_token);
    free(email);
    free(username_seed);
    return ok;
}
