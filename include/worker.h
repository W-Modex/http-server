#ifndef WORKER_H
#define WORKER_H

#include "utils.h"
#include <bits/pthreadtypes.h>
#include <sys/types.h>


typedef struct job {
    int fd;
    char* data;
    struct job* next;
} job_t;

typedef struct job_queue{
    job_t* head;
    job_t* tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} job_queue_t;

typedef struct client {
    int fd;
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
    int fdcount;
    int fdsize;
} cxt_t;

void q_push(job_queue_t* q, job_t* j);
job_t* q_pop(job_queue_t* q);

void* worker_init(void* arg);

#endif