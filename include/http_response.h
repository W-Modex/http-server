#ifndef RESPONDER_H
#define RESPONDER_H

#include "http_parser.h"
#include "worker.h"

typedef struct {
    int status_code;
    char status_text[64];
    char content_type[64];
    char *body;
    size_t body_length;
} http_response_t;


char* handle_response(job_t* j);
char* build_response(http_response_t *res);
char* build_simple_error(int code, const char *text);
char* resolve_path(char* path);
char* mime_type(char* filename);
char* HTTP_GET(http_request_t* req);
char* HTTP_HEAD(http_request_t* req);

#endif