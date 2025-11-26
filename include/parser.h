#ifndef PARSER_H
#define PARSER_H

#define MAX_HEADER 50
#define MAX_LINE 1024

typedef struct {
    char *name;
    char *value;
} Header;

typedef struct {
    char method[16];
    char path[256];
    char version[16];
    Header headers[MAX_HEADER];
    int header_count;
} http_request;

int parse_startline(char* line, http_request* req);
int parse_header(char* line, http_request* req);
http_request* parse_request(char* msg, int client_fd);

#endif