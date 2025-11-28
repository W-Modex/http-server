#include "../include/http_response.h"
#include "network.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_response(char *msg, int client_fd) {
    http_request* req = parse_request(msg, client_fd);
    if (strcmp(req->method, "GET") == 0) {
        HTTP_GET(req, client_fd);
    } else if (strcmp(req->method, "HEAD") == 0) {
        HTTP_HEAD(req, client_fd);
    }
}

void HTTP_GET(http_request *req, int client_fd) {
    char filename[512];
    snprintf(filename, sizeof(filename), "../static%sindex.html", req->path);

    printf("filename: %s\n", filename);
    
    char* buf = file_to_buffer(filename);
    char* res = malloc(strlen(buf) + 200);

    snprintf(res, strlen(buf) + 200,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "%s", buf);

    send_message(client_fd, res, strlen(res));

    free(buf);
    free(res);
}


void HTTP_HEAD(http_request *req, int client_fd) {

}