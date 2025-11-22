#include "parser.h"
#include "network.h"
#include "stdio.h"
#include <string.h>

const char* msg = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<!DOCTYPE html><html><body><h1>meow<h1/><body/><html/>\r\n";

void handle_request(const char *req, int client_fd) {
    printf("%s\n", req);

    int bytes_sent = send_message(client_fd, msg, strlen(msg));
}