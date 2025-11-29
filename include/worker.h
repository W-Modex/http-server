#ifndef WORKER_H
#define WORKER_H

#include <bits/pthreadtypes.h>

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

void q_push(job_queue_t* q, job_t* j);
job_t* q_pop(job_queue_t* q);

void* worker_init(void* arg);

#endif