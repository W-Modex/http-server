#include "../include/clients.h"
#include "../include/worker.h"
#include "utils.h"
#include <asm-generic/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define WORKER_COUNT 15

pthread_t workers[WORKER_COUNT];

int main(int argc, char** argv) {
    int listener = get_listener_fd("2323");
    if (listener < 0) {
        fprintf(stderr, "failed to connect\n");
        exit(EXIT_FAILURE);
    }

    int fdsize = INITIAL_FD_SIZE;
    int fdcount = 0;

    cxt_t* worker_cxt = malloc(sizeof(cxt_t));
    if (!worker_cxt) DIE("malloc worker_cxt");

    job_queue_t* queue = malloc(sizeof(job_queue_t));
    if (!queue) DIE("malloc queue");
    queue->head = NULL;
    queue->tail = NULL;
    if (pthread_mutex_init(&queue->lock, NULL) != 0) DIE("mutex init");
    if (pthread_cond_init(&queue->cond, NULL) != 0) DIE("cond init");

    struct pollfd *pfds = calloc(fdsize, sizeof(struct pollfd));
    if (!pfds) DIE("calloc pfds");
    client_t *clients = calloc(fdsize, sizeof(client_t));
    if (!clients) DIE("calloc clients");

    pfds[0].fd = listener;
    pfds[0].events = POLLIN;
    fdcount++;

    worker_cxt->pfds = pfds;
    if (pthread_mutex_init(&worker_cxt->pfds_lock, NULL) != 0) DIE("pfds_lock init");
    worker_cxt->q = queue;
    worker_cxt->clients = clients;

    worker_cxt->clients[0].fd = listener;
    worker_cxt->clients[0].write_buf = NULL;
    worker_cxt->clients[0].write_len = 0;
    worker_cxt->clients[0].write_send = 0;

    printf("server: waiting for connections...\n");

    for (int i = 0; i < WORKER_COUNT; i++) {
        if (pthread_create(&workers[i], NULL, worker_init, (void*) worker_cxt) != 0)
            DIE("pthread_create");
    }

    while (1) {
        int poll_count = poll(worker_cxt->pfds, fdcount, -1);
        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        process_connections(worker_cxt, listener, &fdcount, &fdsize);
    }

    free(pfds);
    free(clients);
    free(queue);
    free(worker_cxt);

    return 0;
}
