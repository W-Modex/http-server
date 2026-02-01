#include "http/body.h"
#include "http/parser.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

static http_request_t *build_request_with_body(const char *body, const char *content_type) {
    char req[2048];
    if (!body) body = "";
    if (!content_type) content_type = "application/x-www-form-urlencoded";
    size_t body_len = strlen(body);
    int len = snprintf(req, sizeof(req),
        "POST /submit HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        content_type, body_len, body);
    if (len < 0 || (size_t)len >= sizeof(req)) return NULL;
    return parse_http_request(req, (size_t)len);
}

static int test_detect_body_kind_none(void) {
    const char *msg = "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(req->body_kind == BODY_NONE);
    free_http_request(req);
    return 0;
}

static int test_detect_body_kind_json(void) {
    const char *body = "{}";
    http_request_t *req = build_request_with_body(body, "application/json; charset=utf-8");
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(req->body_kind == BODY_JSON);
    free_http_request(req);
    return 0;
}

static int test_parse_form_basic(void) {
    const char *body = "name=john&password=1234";
    http_request_t *req = build_request_with_body(body, NULL);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(http_request_parse_form(req) == 0);
    ASSERT_TRUE(req->form_parsed == 1);
    ASSERT_TRUE(req->form_count == 2);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "name"), "john") == 0);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "password"), "1234") == 0);
    free_http_request(req);
    return 0;
}

static int test_parse_form_percent_plus(void) {
    const char *body = "greeting=hello+world&encoded=%7Bvalue%7D";
    http_request_t *req = build_request_with_body(body, NULL);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(http_request_parse_form(req) == 0);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "greeting"), "hello world") == 0);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "encoded"), "{value}") == 0);
    free_http_request(req);
    return 0;
}

static int test_parse_form_duplicate_key(void) {
    const char *body = "dup=one&dup=two&other=3";
    http_request_t *req = build_request_with_body(body, NULL);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(http_request_parse_form(req) == 0);
    ASSERT_TRUE(req->form_count == 2);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "dup"), "one") == 0);
    ASSERT_TRUE(strcmp(http_request_form_get(req, "other"), "3") == 0);
    free_http_request(req);
    return 0;
}

static int test_parse_form_empty_body(void) {
    const char *body = "";
    http_request_t *req = build_request_with_body(body, NULL);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(http_request_parse_form(req) == 0);
    ASSERT_TRUE(req->form_parsed == 1);
    ASSERT_TRUE(req->form_count == 0);
    free_http_request(req);
    return 0;
}

static int test_parse_form_invalid_percent(void) {
    const char *body = "bad=%ZZ";
    http_request_t *req = build_request_with_body(body, NULL);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(http_request_parse_form(req) == -1);
    ASSERT_TRUE(req->form_parsed == 0);
    ASSERT_TRUE(req->form_count == 0);
    ASSERT_TRUE(req->form_items == NULL);
    free_http_request(req);
    return 0;
}

static int test_parse_form_wrong_content_type(void) {
    const char *body = "a=1";
    http_request_t *req = build_request_with_body(body, "text/plain");
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(req->body_kind == BODY_UNSUPPORTED);
    ASSERT_TRUE(http_request_parse_form(req) == -1);
    free_http_request(req);
    return 0;
}

int main() {
    int failures = 0;
    failures += test_detect_body_kind_none();
    failures += test_detect_body_kind_json();
    failures += test_parse_form_basic();
    failures += test_parse_form_percent_plus();
    failures += test_parse_form_duplicate_key();
    failures += test_parse_form_empty_body();
    failures += test_parse_form_invalid_percent();
    failures += test_parse_form_wrong_content_type();

    if (failures == 0) {
        printf("test_http_body passed!\n");
        return 0;
    }

    printf("test_http_body had %d failure(s)\n", failures);
    return 1;
}
