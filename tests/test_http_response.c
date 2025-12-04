#include "../include/http_response.h"
#include "../include/http_parser.h"
#include "worker.h"
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

int main() {
    job_t* j = malloc(sizeof(job_t));
    j->data = "GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
    j->fd = 3;
    char* buf = handle_response(j);
    ASSERT_TRUE(buf != NULL);
    printf("%s\n", buf);
    printf("test_http_parse passed!\n");
    free(j);
    return 0;
}