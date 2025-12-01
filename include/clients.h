#ifndef CLIENTS_H
#define CLIENTS_H

#include <sys/poll.h>
#include <sys/types.h>
#include "network.h"
#include "utils.h"
#include "worker.h"

void process_connections(cxt_t* cxt, int listener);
void broadcast(cxt_t* cxt, int listener, int idx, char* msg);
void add_connection(cxt_t* cxt, int listener);
void handle_client_read(cxt_t* cxt, int client_fd, int listener);
void handle_client_send(cxt_t* cxt, int client_fd, int listener);
void close_connection(cxt_t* cxt, int client_fd);

#endif