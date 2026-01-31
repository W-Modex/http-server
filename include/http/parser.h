#ifndef PARSER_H
#define PARSER_H

#include "utils/str.h"

typedef struct {
    char *name;
    char *value;
} header_t;

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_UNKNOWN
} http_method_t;

typedef struct {
    http_method_t method;
    char path[MAX_PATH_LEN];
    char version[MAX_METHOD_LEN];
    header_t headers[MAX_HEADER_COUNT];
    int header_count;
    int is_ssl;
    char *body;      
    size_t body_len;
} http_request_t;

http_request_t* parse_http_request(const char *raw, size_t raw_len);
void free_http_request(http_request_t *req);
const char* http_request_get_header(const http_request_t *req, const char *name);

#endif
