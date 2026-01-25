#ifndef PARSER_H
#define PARSER_H

#include "utils.h"

typedef struct {
    char *name;
    char *value;
} header_t;

typedef struct {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char version[MAX_METHOD_LEN];
    header_t headers[MAX_HEADER_COUNT];
    int header_count;
     char *body;      
    size_t body_len;
} http_request_t;

http_request_t* parse_http_request(const char *raw, size_t raw_len);
void free_http_request(http_request_t *req);
const char* http_request_get_header(const http_request_t *req, const char *name);

#endif
