#ifndef RESPONDER_H
#define RESPONDER_H

#include "http_parser.h"

void handle_response(char* msg, int client_fd);
void HTTP_GET(http_request* req, int client_fd);
void HTTP_HEAD(http_request* req, int client_fd);

#endif