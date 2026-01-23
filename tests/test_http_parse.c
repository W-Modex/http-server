#include "../include/http_parser.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

int main() {
    char* msg = "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=john&password=1234";
    http_request_t* req = parse_http_request(msg);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(req->method, "POST") == 0);
    ASSERT_TRUE(strcmp(req->path, "/") == 0);
    ASSERT_TRUE(strcmp(req->version, "1.1"));
    printf("the request body is: %s\n", req->body);
    printf("test_http_parse passed!\n");
    free(req);
    return 0;
}