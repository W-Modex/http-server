#include "auth/csrf.h"
#include "auth/crypto.h"
#include "http/body.h"
#include "utils/str.h"
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CSRF_HMAC_MSG "csrf"

static int str_case_starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (!*s) return 0;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++;
        prefix++;
    }
    return 1;
}

static int str_case_eq_full(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    if (alen != blen) return 0;
    for (size_t i = 0; i < alen; ++i) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    }
    return 1;
}

static int build_expected_origin(const http_request_t *req, char *out, size_t out_len) {
    if (!req || !out || out_len == 0) return 0;
    const char *host = http_request_get_header(req, "Host");
    if (!host || !*host) return 0;
    const char *xfp = http_request_get_header(req, "X-Forwarded-Proto");
    const char *scheme = (req->is_ssl || (xfp && str_case_eq(xfp, "https"))) ? "https" : "http";
    int needed = snprintf(out, out_len, "%s://%s", scheme, host);
    if (needed < 0 || (size_t)needed >= out_len) return 0;
    return 1;
}

static int origin_or_referer_ok(const http_request_t *req) {
    if (!req) return 0;
    const char *origin = http_request_get_header(req, "Origin");
    const char *referer = http_request_get_header(req, "Referer");
    if (!origin && !referer) return 1;

    char expected[512];
    if (!build_expected_origin(req, expected, sizeof(expected))) return 0;

    if (origin) {
        if (strcmp(origin, "null") == 0) return 0;
        return str_case_eq_full(origin, expected);
    }
    if (referer) {
        return str_case_starts_with(referer, expected);
    }
    return 1;
}

static int csrf_hmac(const session_t *session, unsigned char *out, unsigned int *out_len) {
    if (!session || !out || !out_len) return 0;
    unsigned char *digest = HMAC(EVP_sha256(),
        session->csrf_secret, (int)sizeof(session->csrf_secret),
        (const unsigned char *)CSRF_HMAC_MSG, strlen(CSRF_HMAC_MSG),
        out, out_len);
    if (!digest) return 0;
    if (*out_len != CSRF_TOKEN_BYTES) return 0;
    return 1;
}

int csrf_token_hex(const session_t *session, char *out, size_t out_len) {
    if (!session || !out) return 0;
    if (out_len < CSRF_TOKEN_HEX_LEN + 1) return 0;

    unsigned char digest[CSRF_TOKEN_BYTES];
    unsigned int digest_len = 0;
    if (!csrf_hmac(session, digest, &digest_len)) return 0;

    return hex_encode(digest, digest_len, out, out_len) == 0;
}

static const char *csrf_token_from_request(http_request_t *req) {
    if (!req) return NULL;
    const char *token = http_request_get_header(req, CSRF_HEADER_NAME);
    if (token && *token) return token;

    if (http_request_parse_form(req) == 0) {
        token = http_request_form_get(req, CSRF_FIELD_NAME);
        if (token && *token) return token;
    }
    if (http_request_parse_json(req) == 0) {
        token = http_request_json_get(req, CSRF_FIELD_NAME);
        if (token && *token) return token;
    }
    return NULL;
}

int csrf_validate_request(http_request_t *req) {
    if (!req) return 0;
    if (req->session.created_at == 0) return 0;
    if (!origin_or_referer_ok(req)) return 0;

    const char *token = csrf_token_from_request(req);
    if (!token) return 0;
    if (strlen(token) != CSRF_TOKEN_HEX_LEN) return 0;

    unsigned char token_bytes[CSRF_TOKEN_BYTES];
    if (hex_decode(token, token_bytes, sizeof(token_bytes)) != 0) return 0;

    unsigned char expected[CSRF_TOKEN_BYTES];
    unsigned int expected_len = 0;
    if (!csrf_hmac(&req->session, expected, &expected_len)) return 0;

    return CRYPTO_memcmp(token_bytes, expected, CSRF_TOKEN_BYTES) == 0;
}

int csrf_maybe_inject(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;
    if (!res->body || res->body_length == 0) return 1;
    if (!res->content_type[0] || !str_case_starts_with(res->content_type, "text/html")) {
        return 1;
    }

    const char *needle = CSRF_TOKEN_PLACEHOLDER;
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || res->body_length < needle_len) return 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    const char *replacement = "";
    if (req->session.created_at != 0 && csrf_token_hex(&req->session, token, sizeof(token))) {
        replacement = token;
    }

    unsigned char *new_body = NULL;
    size_t new_len = 0;
    if (!replace_all(res->body, res->body_length, needle, replacement, &new_body, &new_len)) {
        return 0;
    }
    if (!new_body) return 1;

    if (res->body_owned && res->body) free((void *)res->body);
    res->body = new_body;
    res->body_length = new_len;
    res->body_owned = 1;
    return 1;
}
