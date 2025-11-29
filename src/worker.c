#include <pthread.h>
#include "../include/worker.h"
#include "../include/http_response.h"

void q_push(job_queue_t *q, job_t* j) {
    if (!q->tail) {
        q->tail = j;
        q->head = j;
    } else {
        q->tail->next = j;
        q->tail = j;
    }
}

job_t* q_pop(job_queue_t *q) {
    job_t *j = q->head;
    q->head = j->next;
    if (q->head == 0) 
        q->tail = 0;
    return j;
}

void* worker_init(void* arg) {
    job_queue_t* q = (job_queue_t*) arg;
    while (1) {
        pthread_mutex_lock(&q->lock);
        while (!q->tail)
            pthread_cond_wait(&q->cond, &q->lock);
        job_t* j = q_pop(q);
        pthread_mutex_unlock(&q->lock);
        handle_response(j);
    }
}