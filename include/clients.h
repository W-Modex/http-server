#ifndef CLIENTS_H
#define CLIENTS_H

#include <sys/poll.h>
#include <sys/types.h>
#include "network.h"
#include "utils.h"
#include "worker.h"

void process_connections(cxt_t* cxt, int listener, int* fdcount, int* fdsize);
void broadcast(struct pollfd* pfds, int listener, int idx, int* fdcount, char* msg);
void add_connection(cxt_t* cxt, int listener, int* fdcount, int* fdsize);
void handle_client_read(cxt_t* cxt, int client_fd, int listener, int* fdcount);
void handle_client_send(cxt_t* cxt, int client_fd, int listener, int* fdcount);
void close_connection(struct pollfd* pfds, int client_fd, int* fdcount);

#endif