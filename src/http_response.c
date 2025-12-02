#include "../include/http_response.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* handle_response(job_t* j) {
    http_request* req = parse_request(j->data);
    if (strcmp(req->method, "GET") == 0) {
        return HTTP_GET(req, j->fd);
    } else if (strcmp(req->method, "HEAD") == 0) {
        return HTTP_HEAD(req, j->fd);
    }
}

char* HTTP_GET(http_request *req, int client_fd) {
    char filename[512];
    snprintf(filename, sizeof(filename), "../static%sindex.html", req->path);

    printf("filename: %s\n", filename);
    
    char* buf = file_to_buffer(filename);
    char* res = malloc(strlen(buf) + 200);

    snprintf(res, strlen(buf) + 200,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "%s", buf);
    
    free(buf);
    return res;
}


char* HTTP_HEAD(http_request *req, int client_fd) {

}