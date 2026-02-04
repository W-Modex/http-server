#ifndef CLIENTS_H
#define CLIENTS_H

#include <sys/poll.h>
#include <sys/types.h>
#include "worker.h"

void process_connections(cxt_t* cxt, int listener, int ssl_listener, const struct pollfd* pfds, int fdcount);
void broadcast(cxt_t* cxt, int listener, int idx, char* msg);
void add_connection(cxt_t* cxt, int listener, int is_ssl);
void handle_client_read(cxt_t* cxt, int client_fd);
void handle_client_send(cxt_t* cxt, int client_fd);
void close_connection(cxt_t* cxt, int client_fd);

#endif
