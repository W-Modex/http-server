#include "../include/http_parser.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

int main() {
    char* msg = "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=john&password=1234";
    http_request_t* req = parse_http_request(msg, strlen(msg));
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(req->method, "POST") == 0);
    ASSERT_TRUE(strcmp(req->path, "/") == 0);
    ASSERT_TRUE(strcmp(req->version, "HTTP/1.1") == 0);
    ASSERT_TRUE(req->body_len == 27);
    printf("the request body is: ");
    fwrite(req->body, 1, req->body_len, stdout);
    printf("\n");
    printf("test_http_parse passed!\n");
    free_http_request(req);
    return 0;
}
