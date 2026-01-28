#include "http/response.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

static int test_build_response_basic(void) {
    http_response_t res;
    http_response_init(&res, 200, "OK");
    http_response_set_body(&res, (const unsigned char *)"hello", 5, "text/plain");
    ASSERT_TRUE(http_response_add_header(&res, "X-Test", "123") == 0);

    http_payload_t payload = build_response(&res);
    http_response_clear(&res);

    ASSERT_TRUE(payload.data != NULL);
    ASSERT_TRUE(strncmp(payload.data, "HTTP/1.1 200 OK\r\n", 17) == 0);
    ASSERT_TRUE(strstr(payload.data, "Content-Type: text/plain\r\n") != NULL);
    ASSERT_TRUE(strstr(payload.data, "Content-Length: 5\r\n") != NULL);
    ASSERT_TRUE(strstr(payload.data, "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n") != NULL);
    ASSERT_TRUE(strstr(payload.data, "X-Test: 123\r\n") != NULL);
    ASSERT_TRUE(strstr(payload.data, "\r\n\r\nhello") != NULL);

    free(payload.data);
    return 0;
}

static int test_default_content_type(void) {
    http_response_t res;
    http_response_init(&res, 204, "No Content");
    http_response_set_body(&res, NULL, 0, NULL);
    http_payload_t payload = build_response(&res);
    http_response_clear(&res);

    ASSERT_TRUE(payload.data != NULL);
    ASSERT_TRUE(strstr(payload.data, "Content-Type: application/octet-stream\r\n") != NULL);

    free(payload.data);
    return 0;
}

static int test_add_header_validation(void) {
    http_response_t res;
    http_response_init(&res, 200, "OK");
    ASSERT_TRUE(http_response_add_header(&res, NULL, "x") == -1);
    ASSERT_TRUE(http_response_add_header(&res, "X", NULL) == -1);
    http_response_clear(&res);
    return 0;
}

static int test_build_simple_error(void) {
    http_payload_t payload = build_simple_error(404, "Not Found");
    ASSERT_TRUE(payload.data != NULL);
    ASSERT_TRUE(strncmp(payload.data, "HTTP/1.1 404 Not Found\r\n", 24) == 0);
    ASSERT_TRUE(strstr(payload.data, "Content-Length: 0\r\n") != NULL);
    free(payload.data);
    return 0;
}

static int test_handle_response_redirect(void) {
    const char *msg = "GET /docs HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";
    http_request_t *req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    http_payload_t payload = handle_response(req, 0);
    free_http_request(req);

    ASSERT_TRUE(payload.data != NULL);
    ASSERT_TRUE(strncmp(payload.data, "HTTP/1.1 308 Permanent Redirect\r\n", 33) == 0);
    ASSERT_TRUE(strstr(payload.data, "Location: https://example.com/docs\r\n") != NULL);
    free(payload.data);
    return 0;
}

int main() {
    int failures = 0;
    failures += test_build_response_basic();
    failures += test_default_content_type();
    failures += test_add_header_validation();
    failures += test_build_simple_error();
    failures += test_handle_response_redirect();

    if (failures == 0) {
        printf("test_http_response passed!\n");
        return 0;
    }

    printf("test_http_response had %d failure(s)\n", failures);
    return 1;
}
