#include "../include/http_parser.h"
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

int main() {
    char* msg = "GET / HTTP 1.1\r\nContent-Type: text/html\r\n\r\n";
    http_request* req = parse_request(msg);
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(strcmp(req->method, "GET") == 0);
    ASSERT_TRUE(strcmp(req->path, "/") == 0);
    ASSERT_TRUE(strcmp(req->version, "1.1"));
    printf("test_http_parse passed!\n");
    free(req);
    return 0;
}