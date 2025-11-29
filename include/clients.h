#ifndef CLIENTS_H
#define CLIENTS_H

#include <sys/poll.h>
#include <sys/types.h>
#include "network.h"
#include "utils.h"
#include "worker.h"

typedef struct client {
    int fd;
    char read_buf[MAX_REQUEST_SIZE];
    char* write_buf;
    ssize_t write_len;
    ssize_t write_send;
} client_t;

void process_connections(struct pollfd** pfds, job_queue_t* q, int listener, int* fdcount, int* fdsize);
void broadcast(struct pollfd ** pfds, int listener, int idx, int* fdcount, char* msg);
void add_connection(struct pollfd** pfds, int listener, int* fdcount, int* fdsize);
void handle_client_read(struct pollfd** pfds, job_queue_t* q, int client_fd, int listener, int* fdcount);
void handle_client_send(struct pollfd** pfds, job_queue_t* q, int client_fd, int listener, int* fdcount);
void close_connection(struct pollfd** pfds, int client_fd, int* fdcount);

#endif