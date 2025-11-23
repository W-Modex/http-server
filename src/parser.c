#include "../include/parser.h"
#include "../include/network.h"
#include <string.h>

const char* msg = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<!DOCTYPE html><html><body><h1>meow<h1/><body/><html/>";

void handle_request(const char *req, int client_fd) {
    int i = 0;
    char buf[100];
    do {
        int j = 0;
        char c = msg[i++];
        if (c == '\r' && msg[i] == '\n') continue;
        buf[j++] = c;
    } while (strlen(buf) != 0);
    int bytes_sent = send_message(client_fd, msg, strlen(msg));
}

