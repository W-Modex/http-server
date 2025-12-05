#include "../include/http_response.h"
#include "worker.h"
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

int main() {
    job_t* j1 = malloc(sizeof(job_t));
    j1->data = "GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
    job_t* j2 = malloc(sizeof(job_t));
    j2->data = "GET /about HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
    job_t* j3 = malloc(sizeof(job_t));
    j3->data = "GET /about/index.css HTTP/1.1\r\nContent-Type: text/css\r\n\r\n";
    char* buf1 = handle_response(j1);
    char* buf2 = handle_response(j2);
    char* buf3 = handle_response(j3);
    printf("%s\n", buf1);
    printf("%s\n", buf2);
    printf("%s\n", buf3);
    printf("test_http_parse passed!\n");
    free(j1);
    return 0;
}