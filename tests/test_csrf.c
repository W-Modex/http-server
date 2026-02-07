#include "auth/csrf.h"
#include "http/request.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

static void set_session_secret(http_request_t *req, unsigned char value) {
    memset(req->session.csrf_secret, value, sizeof(req->session.csrf_secret));
    req->session.created_at = 1;
}

static int build_form_request(char *out, size_t out_len, const char *token,
                              const char *origin, const char *referer) {
    char body[256];
    int body_len = snprintf(body, sizeof(body), "csrf_token=%s", token ? token : "");
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return -1;

    const char *origin_line = origin ? origin : "";
    const char *referer_line = referer ? referer : "";

    int total = snprintf(out, out_len,
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "%s"
        "%s"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        origin_line,
        referer_line,
        body_len,
        body);
    if (total < 0 || (size_t)total >= out_len) return -1;
    return 0;
}

static int build_header_request(char *out, size_t out_len, const char *token,
                                const char *origin, const char *referer) {
    const char *origin_line = origin ? origin : "";
    const char *referer_line = referer ? referer : "";
    const char *token_line = token ? token : "";
    int total = snprintf(out, out_len,
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "%s"
        "%s"
        "%s"
        "Content-Length: 0\r\n"
        "\r\n",
        origin_line,
        referer_line,
        token_line);
    if (total < 0 || (size_t)total >= out_len) return -1;
    return 0;
}

static int test_valid_form_token(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x11, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token,
        "Origin: https://example.com\r\n", NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x11);
    ASSERT_TRUE(csrf_validate_request(req) == 1);
    free_http_request(req);
    return 0;
}

static int test_valid_header_token(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x22, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char token_line[128];
    snprintf(token_line, sizeof(token_line), "X-CSRF-Token: %s\r\n", token);

    char msg[1024];
    ASSERT_TRUE(build_header_request(msg, sizeof(msg), token_line,
        "Origin: https://example.com\r\n", NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x22);
    ASSERT_TRUE(csrf_validate_request(req) == 1);
    free_http_request(req);
    return 0;
}

static int test_missing_token_fails(void) {
    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), "",
        "Origin: https://example.com\r\n", NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x33);
    ASSERT_TRUE(csrf_validate_request(req) == 0);
    free_http_request(req);
    return 0;
}

static int test_mismatched_token_fails(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x44, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token,
        "Origin: https://example.com\r\n", NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x55);
    ASSERT_TRUE(csrf_validate_request(req) == 0);
    free_http_request(req);
    return 0;
}

static int test_origin_mismatch_fails(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x66, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token,
        "Origin: https://evil.com\r\n", NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x66);
    ASSERT_TRUE(csrf_validate_request(req) == 0);
    free_http_request(req);
    return 0;
}

static int test_referer_match_passes(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x68, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token, NULL,
        "Referer: https://example.com/login\r\n") == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x68);
    ASSERT_TRUE(csrf_validate_request(req) == 1);
    free_http_request(req);
    return 0;
}

static int test_referer_mismatch_fails(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x69, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token, NULL,
        "Referer: https://evil.com/attack\r\n") == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x69);
    ASSERT_TRUE(csrf_validate_request(req) == 0);
    free_http_request(req);
    return 0;
}

static int test_missing_origin_referer_allows(void) {
    session_t s = {0};
    memset(s.csrf_secret, 0x77, sizeof(s.csrf_secret));
    s.created_at = 1;

    char token[CSRF_TOKEN_HEX_LEN + 1];
    ASSERT_TRUE(csrf_token_hex(&s, token, sizeof(token)) == 1);

    char msg[1024];
    ASSERT_TRUE(build_form_request(msg, sizeof(msg), token, NULL, NULL) == 0);

    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    req->is_ssl = 1;
    set_session_secret(req, 0x77);
    ASSERT_TRUE(csrf_validate_request(req) == 1);
    free_http_request(req);
    return 0;
}

int main() {
    int failures = 0;
    failures += test_valid_form_token();
    failures += test_valid_header_token();
    failures += test_missing_token_fails();
    failures += test_mismatched_token_fails();
    failures += test_origin_mismatch_fails();
    failures += test_referer_match_passes();
    failures += test_referer_mismatch_fails();
    failures += test_missing_origin_referer_allows();

    if (failures == 0) {
        printf("test_csrf passed!\n");
        return 0;
    }

    printf("test_csrf had %d failure(s)\n", failures);
    return 1;
}
