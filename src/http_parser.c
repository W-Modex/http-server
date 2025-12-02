#include "../include/http_parser.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

http_request* parse_request(char *msg) {
    if (!msg) return NULL;

    http_request* req = calloc(1, sizeof(http_request));
    if (!req) return NULL;

    char* data = strdup(msg);
    if (!data) { free(req); return NULL; }

    char *saveptr = NULL;
    char *line = strtok_r(data, "\r\n", &saveptr);
    if (!line) {
        free(data);
        free(req);
        return NULL;
    }

    if (parse_startline(line, req) != 0) {
        free(data);
        free(req);
        return NULL;
    }

    req->header_count = 0;

    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        str_trim(line);
        if (strlen(line) == 0) break;
        if (!strchr(line, ':')) break;          
        if (parse_header(line, req) != 0) break;
    }

    free(data);
    return req;
}

int parse_startline(char *msg, http_request* req) {
    if (!msg || !req) return -1;

    char *saveptr = NULL;
    char *method = strtok_r(msg, " ", &saveptr);
    char *path = strtok_r(NULL, " ", &saveptr);
    char *version = strtok_r(NULL, " ", &saveptr);

    if (!method || !path || !version) return -1;

    strncpy(req->method, method, sizeof(req->method) - 1);
    req->method[sizeof(req->method) - 1] = '\0';
    strncpy(req->path, path, sizeof(req->path) - 1);
    req->path[sizeof(req->path) - 1] = '\0';
    strncpy(req->version, version, sizeof(req->version) - 1);
    req->version[sizeof(req->version) - 1] = '\0';

    return 0;
}

int parse_header(char* line, http_request* req) {
    if (!line || !req) return -1;
    if (req->header_count >= MAX_HEADER_COUNT) return -1;

    char* colon = strchr(line, ':');
    if (!colon) return -1;
    *colon = '\0';
    str_trim(line);
    str_trim(colon + 1);
    req->headers[req->header_count].name = strdup(line);
    req->headers[req->header_count].value = strdup(colon+1);
    if (!req->headers[req->header_count].name || !req->headers[req->header_count].value) {
        free(req->headers[req->header_count].name);
        free(req->headers[req->header_count].value);
        return -1;
    }
    req->header_count++;

    return 0;
}
