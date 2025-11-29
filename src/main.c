#include "../include/clients.h"
#include "../include/worker.h"
#include <asm-generic/socket.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

typedef struct cxt {
    struct pollfd* pfds;
    pthread_mutex_t pfds_lock;
    job_queue_t* q;
    client_t clients[MAX_CLIENTS];
} cxt_t;

pthread_t workers[15];
pthread_mutex_t job_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pfds_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

int main(int argc, char** argv) {
    int listener = get_listener_fd("2323");
    
    if (listener < 0) {
        fprintf(stderr, "failed to connect\n");
        exit(EXIT_FAILURE);
    }

    int fdsize = 10;
    int fdcount = 0;
    
    job_queue_t* queue = malloc(sizeof(job_queue_t));
    queue->head = NULL;
    queue->tail = NULL;
    queue->lock = job_lock;
    queue->cond = job_cond;

    struct pollfd *pfds = malloc(sizeof(struct pollfd) * fdsize);
    pfds[0].fd = listener;
    pfds[0].events = POLLIN;
    fdcount++;

    printf("server: waiting for connections...\n");

    for (int i = 0; i < 15; i++) 
        pthread_create(&(workers[i]), NULL, (void*) worker_init, (void*)&queue);
  
    
    while (1) {
        int poll_count = poll(pfds, fdcount, -1);

        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }
        process_connections(&pfds, queue, listener, &fdcount, &fdsize);
    }

    free(pfds);
    return 0;
}