#ifndef PARSER_H
#define PARSER_H

#include "utils.h"

typedef struct {
    char *name;
    char *value;
} Header;

typedef struct {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char version[MAX_METHOD_LEN];
    Header headers[MAX_HEADER_COUNT];
    int header_count;
} http_request;

int parse_startline(char* line, http_request* req);
int parse_header(char* line, http_request* req);
http_request* parse_request(char* msg, int client_fd);

#endif