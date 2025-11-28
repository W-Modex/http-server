#ifndef CLIENTS_H
#define CLIENTS_H

#include <sys/poll.h>
#include "network.h"

void process_connections(struct pollfd** pfds, int listener, int* fdcount, int* fdsize);
void broadcast(struct pollfd ** pfds, int listener, int idx, int* fdcount, char* msg);
void add_connection(struct pollfd** pfds, int listener, int* fdcount, int* fdsize);
void handle_client(struct pollfd** pfds, int client_fd, int listener, int* fdcount);
void close_connection(struct pollfd** pfds, int client_fd, int* fdcount);

#endif