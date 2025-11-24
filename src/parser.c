#include "../include/parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* msg = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<!DOCTYPE html><html><body><h1>meow<h1/><body/><html/>";

char* trim(char *str) {
    while(*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) - 1;
    while(end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return str;
}

http_request* parse_request(char *msg) {
    http_request* req = malloc(sizeof(http_request));
    char* data = strdup(msg);
    char* line = strtok(data, "\n");
    if (!line) {
        free(data);
        return NULL;
    }

    if (parse_startline(line, req) != 0) {
        free(data);
        return NULL;
    }

    req->header_count = 0;

    while ((line = strtok(NULL, "\n")) != NULL) {
        line = trim(line);
        if (strlen(line) == 0) break;
        parse_header(line, req);
    }

    printf("request method is: %s\n", req->method);
    printf("request path is: %s\n", req->path);
    printf("request version is: %s\n", req->version);
    for (int i = 0; i < req->header_count; i++) 
        printf("header%d: %s:%s\n", i+1, req->headers[i].name, req->headers[i].value);

    free(data);
    return req;
}

int parse_startline(char *msg, http_request* req) {
    char* method = strtok(msg, " ");
    char* path = strtok(NULL, " ");
    char* version = strtok(NULL, " ");

    if (!method || !path || !version) return -1;

    strncpy(req->method, method, sizeof(req->method)-1);
    strncpy(req->path, path, sizeof(req->path)-1);
    strncpy(req->version, version, sizeof(req->version)-1);

    return 0;
}

int parse_header(char* line, http_request* req) {
    if (req->header_count >= MAX_HEADER) return -1;
    
    char* colon = strchr(line, ':');
    if (!colon) return -1;
    req->headers[req->header_count].name = strdup(trim(line));
    req->headers[req->header_count].value = strdup(trim(colon+1));
    req->header_count++;

    return 0;
}