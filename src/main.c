#include "../include/clients.h"
#include "../include/worker.h"
#include <asm-generic/socket.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

pthread_t workers[16];

int main(int argc, char** argv) {
    int listener = get_listener_fd("2323");
    
    if (listener < 0) {
        fprintf(stderr, "failed to connect\n");
        exit(EXIT_FAILURE);
    }

    int fdsize = 10;
    int fdcount = 0;
    
    struct pollfd *pfds = malloc(sizeof(struct pollfd) * fdsize);
    pfds[0].fd = listener;
    pfds[0].events = POLLIN;
    fdcount++;

    printf("server: waiting for connections...\n");

    

    for (int i = 0; i < 16; i++) {
        pthread_create(&(workers[i]), NULL, worker_init(), NULL);
    }
    
    while (1) {
        int poll_count = poll(pfds, fdcount, -1);

        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }
        process_connections(&pfds, listener, &fdcount, &fdsize);
    }

    free(pfds);
    return 0;
}