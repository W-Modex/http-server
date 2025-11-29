#include "../include/clients.h"
#include "network.h"
#include "utils.h"
#include "worker.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_connections(struct pollfd **pfds, job_queue_t* q, int listener, int *fdcount, int *fdsize) {
    for (int i = 0; i < *fdcount; i++) {
        if ((*pfds)[i].revents & (POLLIN | POLLHUP | POLLOUT)) {
            if ((*pfds)[i].fd == listener) {
                add_connection(pfds, listener, fdcount, fdsize);
            } else {
                if ((*pfds)[i].revents & POLLOUT) 
                handle_client_send(pfds, q, (*pfds)[i].fd, listener, fdcount);
                else handle_client_read(pfds, q, (*pfds)[i].fd, listener, fdcount);
            }
        }
    }
}

void broadcast(struct pollfd ** pfds, int listener, int idx, int* fdcount, char* msg) {
    for (int i = 0; i < *fdcount; i++) {
        if ((*pfds)[i].fd == listener || idx == i) continue;
        int bytes_sent = send_message((*pfds)[i].fd, msg, strlen(msg));
        if (bytes_sent == -1) {  
            perror("failed to send message");
            exit(1);
        }
    }
}

void add_connection(struct pollfd **pfds, int listener, int *fdcount, int *fdsize) {
    int client_fd = accept_client(listener);
    if (client_fd < 0) {
        perror("failed to accept client");
        exit(1);
    }

    if (*fdcount == *fdsize) {
        *fdsize *= 2;
        *pfds = realloc(*pfds, *fdsize * sizeof(struct pollfd));
    }

    (*pfds)[*fdcount].fd = client_fd;
    (*pfds)[*fdcount].events = POLLIN;
    (*pfds)[*fdcount].revents = 0;
    (*fdcount)++;
}

void handle_client_read(struct pollfd **pfds, job_queue_t* q, int client_fd, int listener, int* fdcount) {
    char buf[MAX_REQUEST_SIZE];
    int bytes_recv = recv_message(client_fd, buf, MAX_REQUEST_SIZE - 1);

    if (bytes_recv < 0) {
        perror("failed to recv message");
        exit(1);
    }

    if (bytes_recv == 0) {
        close_connection(pfds, client_fd, fdcount);
        return;
    }

    buf[bytes_recv] = '\0';
    job_t* j = malloc(sizeof(job_t));
    j->fd = client_fd;
    j->data = strdup(buf);

    pthread_mutex_lock(&q->lock);
    q_push(q, j);
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

void handle_client_send(struct pollfd **pfds, job_queue_t *q, int client_fd, int listener, int *fdcount) {

}

void close_connection(struct pollfd **pfds, int client_fd, int *fdcount) {
    for (int i = 0; i < *fdcount; i++) {
        if ((*pfds)[i].fd == client_fd) {
            (*pfds)[i] = (*pfds)[*fdcount-1];
            (*fdcount)--;
            break;
        }
    }
}