#include "http/parser.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
    printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
    return 1; \
    }

static int test_post_with_body(void) {
    const char *msg = "POST / HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 27\r\n"
        "\r\n"
        "username=john&password=1234";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(req->method, "POST") == 0);
    ASSERT_TRUE(strcmp(req->path, "/") == 0);
    ASSERT_TRUE(strcmp(req->version, "HTTP/1.1") == 0);
    ASSERT_TRUE(req->body_len == 27);
    ASSERT_TRUE(memcmp(req->body, "username=john&password=1234", 27) == 0);
    ASSERT_TRUE(strcmp(http_request_get_header(req, "Content-Type"),
        "application/x-www-form-urlencoded") == 0);
    free_http_request(req);
    return 0;
}

static int test_get_no_body(void) {
    const char *msg = "GET /index.html HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(req->method, "GET") == 0);
    ASSERT_TRUE(strcmp(req->path, "/index.html") == 0);
    ASSERT_TRUE(strcmp(req->version, "HTTP/1.0") == 0);
    ASSERT_TRUE(req->body_len == 0);
    ASSERT_TRUE(req->body == NULL);
    ASSERT_TRUE(strcmp(http_request_get_header(req, "Host"), "example.com") == 0);
    free_http_request(req);
    return 0;
}

static int test_body_without_content_length(void) {
    const char *msg = "PUT /upload HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n"
        "hi";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(req->body_len == 2);
    ASSERT_TRUE(memcmp(req->body, "hi", 2) == 0);
    free_http_request(req);
    return 0;
}

static int test_header_case_insensitive(void) {
    const char *msg = "GET / HTTP/1.1\r\n"
        "x-forwarded-proto: https\r\n"
        "Host: example.com\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(http_request_get_header(req, "X-Forwarded-Proto"), "https") == 0);
    free_http_request(req);
    return 0;
}

static int test_invalid_content_length(void) {
    const char *msg = "POST / HTTP/1.1\r\n"
        "Content-Length: abc\r\n"
        "\r\n"
        "hello";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req == NULL);
    return 0;
}

static int test_invalid_start_line(void) {
    const char *msg = "GET /index.html\r\n"
        "Host: example.com\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req == NULL);
    return 0;
}

static int test_invalid_header_line(void) {
    const char *msg = "GET / HTTP/1.1\r\n"
        "BadHeader\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req == NULL);
    return 0;
}

static int test_content_length_too_large(void) {
    const char *msg = "POST / HTTP/1.1\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "short";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req == NULL);
    return 0;
}

int main() {
    int failures = 0;
    failures += test_post_with_body();
    failures += test_get_no_body();
    failures += test_body_without_content_length();
    failures += test_header_case_insensitive();
    failures += test_invalid_content_length();
    failures += test_invalid_start_line();
    failures += test_invalid_header_line();
    failures += test_content_length_too_large();

    if (failures == 0) {
        printf("test_http_parse passed!\n");
        return 0;
    }

    printf("test_http_parse had %d failure(s)\n", failures);
    return 1;
}
