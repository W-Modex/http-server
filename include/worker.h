#ifndef WORKER_H
#define WORKER_H

#include "http/response.h"
#include "utils/str.h"
#include <bits/pthreadtypes.h>
#include <openssl/ssl.h>
#include <sys/types.h>


typedef struct job {
    int fd;
    char* data;
    size_t data_len;
    struct job* next;
} job_t;

typedef struct job_queue{
    job_t* head;
    job_t* tail;
    size_t len;
    size_t max;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t not_full;
} job_queue_t;

typedef struct client {
    int fd;
    int is_ssl;
    SSL* ssl;
    char read_buf[MAX_REQUEST_SIZE];
    char* write_buf;
    ssize_t write_len;
    ssize_t write_send;
} client_t;

typedef struct Cxt {
    struct pollfd* pfds;
    pthread_mutex_t pfds_lock;
    job_queue_t* q;
    client_t* clients;
    SSL_CTX* ssl_ctx;
    int fdcount;
    int fdsize;
} cxt_t;

void q_push(job_queue_t* q, job_t* j);
job_t* q_pop(job_queue_t* q);

void setup_write(cxt_t* ctx, http_payload_t* payload, job_t* j);
void* process_jobs(void* arg);

#endif
