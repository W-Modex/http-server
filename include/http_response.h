#ifndef RESPONDER_H
#define RESPONDER_H

#include "http_parser.h"
#include "worker.h"

void handle_response(job_t* j);
void HTTP_GET(http_request* req, int client_fd);
void HTTP_HEAD(http_request* req, int client_fd);

#endif