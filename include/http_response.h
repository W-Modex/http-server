#ifndef RESPONDER_H
#define RESPONDER_H

#include "http_parser.h"
#include "worker.h"

char* handle_response(job_t* j);
char* HTTP_GET(http_request* req, int client_fd);
char* HTTP_HEAD(http_request* req, int client_fd);

#endif