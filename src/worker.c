#include <pthread.h>
#include <stdlib.h>
#include <sys/poll.h>
#include "worker.h"
#include "db.h"
#include "db_ctx.h"
#include "http/response.h"
#include "utils/str.h"

void q_push(job_queue_t *q, job_t* j) {
    if (!q->tail) {
        q->tail = j;
        q->head = j;
    } else {
        q->tail->next = j;
        q->tail = j;
    }
    q->len++;
}

job_t* q_pop(job_queue_t *q) {
    if (!q->head) return NULL;
    job_t* j = q->head;
    q->head = j->next;
    if (q->head == 0) 
        q->tail = 0;
    if (q->len > 0) q->len--;
    return j;
}

void* process_jobs(void* arg) {
    cxt_t* cxt = (cxt_t*) arg;
    PGconn* db = db_connect(must_getenv("DATABASE_URL"));
    if (!db) DIE("db_connect failed");
    if (!db_prepare_all(db)) {
        db_disconnect(db);
        DIE("db_prepare_all failed");
    }
    db_ctx_set(db);
    while (1) {
        pthread_mutex_lock(&cxt->q->lock);
        while (!cxt->q->tail)
            pthread_cond_wait(&cxt->q->cond, &cxt->q->lock);
        job_t* j = q_pop(cxt->q);
        pthread_cond_signal(&cxt->q->not_full);
        pthread_mutex_unlock(&cxt->q->lock);
        if (!j) continue;
        http_request_t* req = parse_http_request(j->data, j->data_len);
        if (req) {
            pthread_mutex_lock(&cxt->pfds_lock);
            for (int i = 0; i < cxt->fdcount; i++) {
                if (cxt->clients[i].fd == j->fd) {
                    req->is_ssl = cxt->clients[i].is_ssl != 0;
                    break;
                }
            }
            pthread_mutex_unlock(&cxt->pfds_lock);
        }
        http_payload_t* payload = malloc(sizeof(http_payload_t));
        if (!payload) {
            if (req) free_http_request(req);
            free(j->data);
            free(j);
            continue;
        }
        if (!handle_response(req, payload))
            build_simple_error(500, "Internal Server Error", payload);
             
        if (req) free_http_request(req);
        setup_write(cxt, payload, j);
        free(payload);
        free(j->data);
        free(j);
    }
}

void setup_write(cxt_t *cxt, http_payload_t* payload, job_t* j) {
    pthread_mutex_lock(&cxt->pfds_lock);
        int found = 0;
        for (int i = 0; i < cxt->fdcount; i++) {
            if (cxt->clients[i].fd == j->fd) {
                if (cxt->clients[i].write_buf)
                    free(cxt->clients[i].write_buf);
                cxt->clients[i].write_buf = payload->data;
                cxt->clients[i].write_len = (ssize_t)payload->length;
                cxt->clients[i].write_send = 0;
                cxt->pfds[i].events |= POLLOUT;
                cxt->pfds[i].events &= ~POLLIN;
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&cxt->pfds_lock);
        if (!found) free(payload->data);
}
