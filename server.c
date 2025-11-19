#include <asm-generic/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char** argv) {
    struct addrinfo hints, *res, *p;
    int listener, yes=1;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, "2323", &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    for (p = res; p != NULL; p = p->ai_next) {
        if ((listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            close(listener);
            perror("setsockopt");
            exit(1);
        }
        if (bind(listener, p->ai_addr , p->ai_addrlen) == -1) {
            close(listener);
            perror("bind");
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (p == NULL) {
        perror("server: failed to bind\n");
        exit(1);
    }

    if (listen(listener, 5) == -1) {
        perror("failed to listen");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    const char* msg = 
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Modex</title></head>"
    "<body><h1>Yo gurt</h1></body></html>";

    while (1) {
        int * client_fd = malloc(sizeof(int));
        struct sockaddr_storage client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        *client_fd = accept(listener, (struct sockaddr*)&client_addr, &client_addr_size);
        if (*client_fd == -1) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        int bytes_sent = send(*client_fd, msg, strlen(msg), 0);
        if (bytes_sent <= 0) {
            printf("failed to send msg\n");
        }
        printf("message have been sent\n");
        close(*client_fd);
    }
    close(listener);
    return 0;
}