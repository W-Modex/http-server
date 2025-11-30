#include "../include/clients.h"
#include "network.h"
#include "utils.h"
#include "worker.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* iterate pfds in the cxt and dispatch read/send */
void process_connections(cxt_t* cxt, int listener, int *fdcount, int *fdsize) {
    for (int i = 0; i < *fdcount; i++) {
        short re = cxt->pfds[i].revents;
        if (re & (POLLIN | POLLHUP | POLLOUT)) {
            if (cxt->pfds[i].fd == listener) {
                add_connection(cxt, listener, fdcount, fdsize);
            } else {
                if (re & POLLOUT)
                    handle_client_send(cxt, cxt->pfds[i].fd, listener, fdcount);
                else if (re & POLLIN)
                    handle_client_read(cxt, cxt->pfds[i].fd, listener, fdcount);
            }
        }
    }
}

void broadcast(struct pollfd* pfds, int listener, int idx, int* fdcount, char* msg) {
    for (int i = 0; i < *fdcount; i++) {
        if (pfds[i].fd == listener || idx == i) continue;
        int bytes_sent = send_message(pfds[i].fd, msg, strlen(msg));
        if (bytes_sent == -1) {
            perror("failed to send message");
            close_connection(pfds, pfds[i].fd, fdcount);
        }
    }
}

/* add a new connection — resize pfds & clients arrays if needed */
void add_connection(cxt_t* cxt, int listener, int *fdcount, int *fdsize) {
    int client_fd = accept_client(listener);
    if (client_fd < 0) {
        perror("failed to accept client");
        return;
    }

    /* we must lock because pfds and clients may be accessed concurrently */
    pthread_mutex_lock(&cxt->pfds_lock);

    if (*fdcount == *fdsize) {
        int new_size = (*fdsize) * 2;
        struct pollfd *new_pfds = realloc(cxt->pfds, new_size * sizeof(struct pollfd));
        if (!new_pfds) { perror("realloc pfds"); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        cxt->pfds = new_pfds;

        client_t *new_clients = realloc(cxt->clients, new_size * sizeof(client_t));
        if (!new_clients) { perror("realloc clients"); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        cxt->clients = new_clients;

        *fdsize = new_size;
    }

    /* initialize client slot */
    cxt->clients[*fdcount].fd = client_fd;
    cxt->clients[*fdcount].write_buf = NULL;
    cxt->clients[*fdcount].write_len = 0;
    cxt->clients[*fdcount].write_send = 0;
    memset(cxt->clients[*fdcount].read_buf, 0, MAX_REQUEST_SIZE);

    /* add to pfds array */
    cxt->pfds[*fdcount].fd = client_fd;
    cxt->pfds[*fdcount].events = POLLIN;
    cxt->pfds[*fdcount].revents = 0;
    (*fdcount)++;

    pthread_mutex_unlock(&cxt->pfds_lock);
}

/* read incoming data and push a job (producer) */
void handle_client_read(cxt_t* cxt, int client_fd, int listener, int* fdcount) {
    char buf[MAX_REQUEST_SIZE];
    int bytes_recv = recv_message(client_fd, buf, MAX_REQUEST_SIZE - 1);

    if (bytes_recv < 0) {
        perror("failed to recv message");
        return;
    }

    if (bytes_recv == 0) {
        /* client closed connection */
        close_connection(cxt->pfds, client_fd, fdcount);
        return;
    }

    buf[bytes_recv] = '\0';

    /* create job and copy data */
    job_t* j = malloc(sizeof(job_t));
    if (!j) { perror("malloc job"); return; }
    j->fd = client_fd;
    j->data = strdup(buf);
    j->next = NULL;

    /* push job into the shared queue (producer) */
    pthread_mutex_lock(&cxt->q->lock);
    q_push(cxt->q, j);
    pthread_cond_signal(&cxt->q->cond);
    pthread_mutex_unlock(&cxt->q->lock);
}

/* called from poll loop when POLLOUT is set for a client */
void handle_client_send(cxt_t* cxt, int client_fd, int listener, int *fdcount) {
    /* find the client index (we keep pfds & clients aligned) */
    int idx = -1;
    for (int i = 0; i < *fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) { idx = i; break; }
    }
    if (idx == -1) return;

    client_t *c = &cxt->clients[idx];
    if (!c->write_buf || c->write_len == 0) {
        /* nothing to send — disable POLLOUT */
        cxt->pfds[idx].events &= ~POLLOUT;
        cxt->pfds[idx].events |= POLLIN;
        return;
    }

    ssize_t to_send = c->write_len - c->write_send;
    ssize_t sent = send(c->fd, c->write_buf + c->write_send, to_send, 0);
    if (sent <= 0) {
        if (sent == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            /* try later */
            return;
        }
        /* error or connection closed */
        close_connection(cxt->pfds, client_fd, fdcount);
        return;
    }

    c->write_send += sent;
    if (c->write_send >= c->write_len) {

        free(c->write_buf);
        c->write_buf = NULL;
        c->write_len = 0;
        c->write_send = 0;

        cxt->pfds[idx].events &= ~POLLOUT;
        cxt->pfds[idx].events |= POLLIN;
    }
}

void close_connection(struct pollfd* pfds, int client_fd, int *fdcount) {
    for (int i = 0; i < *fdcount; i++) {
        if (pfds[i].fd == client_fd) {
            close(client_fd); 

            pfds[i] = pfds[*fdcount - 1];

            (*fdcount)--;
            break;
        }
    }
}
