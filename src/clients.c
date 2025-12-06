#include "../include/clients.h"
#include <fcntl.h>
#include "network.h"
#include "utils.h"
#include "worker.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void process_connections(cxt_t* cxt, int listener) {
    struct pollfd *local_pfds = NULL;
    int local_fdcount = 0;

    pthread_mutex_lock(&cxt->pfds_lock);
    local_fdcount = cxt->fdcount;
    if (local_fdcount > 0) {
        local_pfds = malloc(sizeof(struct pollfd) * local_fdcount);
        if (local_pfds) {
            memcpy(local_pfds, cxt->pfds, sizeof(struct pollfd) * local_fdcount);
        }
    }
    pthread_mutex_unlock(&cxt->pfds_lock);

    if (!local_pfds) return;

    for (int i = 0; i < local_fdcount; ++i) {
        short re = local_pfds[i].revents;
        int fd = local_pfds[i].fd;

        if (re & (POLLIN | POLLHUP | POLLOUT)) {
            if (fd == listener) {
                add_connection(cxt, listener);
            } else {
                if (re & POLLOUT)
                    handle_client_send(cxt, fd, listener);
                else if (re & POLLIN)
                    handle_client_read(cxt, fd, listener);
            }
        }
    }

    free(local_pfds);
}

void add_connection(cxt_t* cxt, int listener) {
    int client_fd = accept_client(listener);
    if (client_fd < 0) {
        perror("failed to accept client");
        return;
    }
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    pthread_mutex_lock(&cxt->pfds_lock);

    if (cxt->fdcount == cxt->fdsize) {
        int new_size = cxt->fdsize * 2;
        struct pollfd *new_pfds = realloc(cxt->pfds, new_size * sizeof(struct pollfd));
        if (!new_pfds) { perror("realloc pfds"); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        cxt->pfds = new_pfds;

        client_t *new_clients = realloc(cxt->clients, new_size * sizeof(client_t));
        if (!new_clients) { perror("realloc clients"); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        size_t old = cxt->fdsize;
        cxt->clients = new_clients;
        if (new_size > old) {
            memset(&cxt->clients[old], 0, (new_size - old) * sizeof(client_t));
        }

    }

    cxt->clients[cxt->fdcount].fd = client_fd;
    cxt->clients[cxt->fdcount].write_buf = NULL;
    cxt->clients[cxt->fdcount].write_len = 0;
    cxt->clients[cxt->fdcount].write_send = 0;
    memset(cxt->clients[cxt->fdcount].read_buf, 0, MAX_REQUEST_SIZE);

    cxt->pfds[cxt->fdcount].fd = client_fd;
    cxt->pfds[cxt->fdcount].events = POLLIN;
    cxt->pfds[cxt->fdcount].revents = 0;
    cxt->fdcount++;

    pthread_mutex_unlock(&cxt->pfds_lock);
}

void handle_client_read(cxt_t* cxt, int client_fd, int listener) {
    char buf[MAX_REQUEST_SIZE];
    int bytes_recv = recv_message(client_fd, buf, MAX_REQUEST_SIZE - 1);

    if (bytes_recv < 0) {
        perror("failed to recv message");
        return;
    }

    if (bytes_recv == 0) {
        close_connection(cxt, client_fd);
        return;
    }

    buf[bytes_recv] = '\0';

    job_t* j = malloc(sizeof(job_t));
    if (!j) { perror("malloc job"); return; }
    j->fd = client_fd;
    j->data = strdup(buf);
    j->next = NULL;

    pthread_mutex_lock(&cxt->q->lock);
    q_push(cxt->q, j);
    pthread_cond_signal(&cxt->q->cond);
    pthread_mutex_unlock(&cxt->q->lock);
}

void handle_client_send(cxt_t* cxt, int client_fd, int listener) {
    pthread_mutex_lock(&cxt->pfds_lock);

    int idx = -1;
    for (int i = 0; i < cxt->fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) { idx = i; break; }
    }
    if (idx == -1) { pthread_mutex_unlock(&cxt->pfds_lock); return; }

    client_t *c = &cxt->clients[idx];
    if (!c->write_buf || c->write_len == 0) {
        cxt->pfds[idx].events &= ~POLLOUT;
        cxt->pfds[idx].events |= POLLIN;
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    }

    ssize_t to_send = c->write_len - c->write_send;
    ssize_t sent = send_message(c->fd, c->write_buf + c->write_send, to_send);

    if (sent <= 0) {
        if (sent == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            pthread_mutex_unlock(&cxt->pfds_lock);
            return;
        }
        if (c->write_buf) { free(c->write_buf); c->write_buf = NULL; }
        cxt->pfds[idx] = cxt->pfds[cxt->fdcount - 1];
        cxt->clients[idx] = cxt->clients[cxt->fdcount - 1];
        cxt->fdcount--;
        pthread_mutex_unlock(&cxt->pfds_lock);
        close(client_fd);
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

    pthread_mutex_unlock(&cxt->pfds_lock);
}


void close_connection(cxt_t* cxt, int client_fd) {
    pthread_mutex_lock(&cxt->pfds_lock);
    for (int i = 0; i < cxt->fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) {
            close(client_fd); 
            cxt->pfds[i] = cxt->pfds[cxt->fdcount - 1];
            cxt->clients[i] = cxt->clients[cxt->fdcount - 1];
            cxt->fdcount--;
            break;
        }
    }
    pthread_mutex_unlock(&cxt->pfds_lock);
}
