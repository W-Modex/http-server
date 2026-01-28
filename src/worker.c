#include <pthread.h>
#include <sys/poll.h>
#include "../include/worker.h"
#include "../include/http/response.h"
#include "../include/http/parser.h"

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
    job_t* j = q->head;
    q->head = j->next;
    if (q->head == 0) 
        q->tail = 0;
    return j;
}

void* process_jobs(void* arg) {
    cxt_t* cxt = (cxt_t*) arg;
    while (1) {
        pthread_mutex_lock(&cxt->q->lock);
        while (!cxt->q->tail)
            pthread_cond_wait(&cxt->q->cond, &cxt->q->lock);
        job_t* j = q_pop(cxt->q);
        pthread_mutex_unlock(&cxt->q->lock);
        if (!j) continue;
        int is_ssl = 0;
        pthread_mutex_lock(&cxt->pfds_lock);
        for (int i = 0; i < cxt->fdcount; i++) {
            if (cxt->clients[i].fd == j->fd) {
                is_ssl = cxt->clients[i].is_ssl != 0;
                break;
            }
        }
        pthread_mutex_unlock(&cxt->pfds_lock);
        http_request_t* req = parse_http_request(j->data, j->data_len);
        http_payload_t payload = handle_response(req, is_ssl);
        if (req) free_http_request(req);
        pthread_mutex_lock(&cxt->pfds_lock);
        int found = 0;
        for (int i = 0; i < cxt->fdcount; i++) {
            if (cxt->clients[i].fd == j->fd) {
                if (cxt->clients[i].write_buf)
                    free(cxt->clients[i].write_buf);
                cxt->clients[i].write_buf = payload.data;
                cxt->clients[i].write_len = (ssize_t)payload.length;
                cxt->clients[i].write_send = 0;
                cxt->pfds[i].events |= POLLOUT;
                cxt->pfds[i].events &= ~POLLIN;
                found = 1;
                break;
            }
        }
        if (!found) free(payload.data);
        pthread_mutex_unlock(&cxt->pfds_lock);
        free(j->data);
        free(j);
    }
}
