#include "../include/responder.h"
#include "network.h"
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

    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("path does not exist");
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* buf = malloc(file_size + 1);
    fread(buf, 1, file_size, f);
    buf[file_size] = '\0';
    fclose(f);

    char* res = malloc(file_size + 200);
    snprintf(res, file_size + 200,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "%s", buf);

    send_message(client_fd, res, strlen(res));

    free(buf);
    free(res);
}


void HTTP_HEAD(http_request *req, int client_fd) {

}