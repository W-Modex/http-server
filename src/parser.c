#include "../include/parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* trim(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return str;
}

http_request* parse_request(char *msg, int client_fd) {
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
        line = trim(line);
        if (strlen(line) == 0) break;
        if (!strchr(line, ':')) break;          
        if (parse_header(line, req) != 0) break;
    }

    printf("request method is: %s\n", req->method);
    printf("request path is: %s\n", req->path);
    printf("request version is: %s\n", req->version);
    for (int i = 0; i < req->header_count; i++)
        printf("header%d: %s:%s\n", i + 1, req->headers[i].name, req->headers[i].value);

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
    if (req->header_count >= MAX_HEADER) return -1;

    char* colon = strchr(line, ':');
    if (!colon) return -1;
    *colon = '\0';
    req->headers[req->header_count].name = strdup(trim(line));
    req->headers[req->header_count].value = strdup(trim(colon + 1));
    if (!req->headers[req->header_count].name || !req->headers[req->header_count].value) {
        free(req->headers[req->header_count].name);
        free(req->headers[req->header_count].value);
        return -1;
    }
    req->header_count++;

    return 0;
}
