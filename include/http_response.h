#ifndef RESPONDER_H
#define RESPONDER_H

#include "http_parser.h"
#include "worker.h"

typedef struct {
    char *name;
    char *value;
} http_response_header_t;

typedef struct {
    int status_code;
    char status_text[64];
    char content_type[64];
    http_response_header_t headers[MAX_RESPONSE_HEADERS];
    int header_count;
    const unsigned char *body;
    size_t body_length;
} http_response_t;

typedef struct {
    char *data;
    size_t length;
} http_payload_t;

void http_response_init(http_response_t *res, int status_code, const char *status_text);
int http_response_add_header(http_response_t *res, const char *name, const char *value);
void http_response_set_body(http_response_t *res, const unsigned char *body, size_t body_length, const char *content_type);
void http_response_clear(http_response_t *res);

http_payload_t handle_response(http_request_t* req, int is_ssl);
http_payload_t build_response(http_response_t *res);
http_payload_t build_simple_error(int code, const char *text);
char* resolve_path(char* path);
char* mime_type(char* filename);
http_payload_t HTTP_GET(http_request_t* req);
http_payload_t HTTP_HEAD(http_request_t* req);
http_payload_t HTTP_POST(http_request_t* req);

#endif
