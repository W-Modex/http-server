#include "../include/clients.h"
#include "../include/worker.h"
#include "network.h"
#include "utils.h"
#include <asm-generic/socket.h>
#include <iso646.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/poll.h>
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
    int ssl_listener = get_listener_fd("3434");
    if (listener < 0 || ssl_listener < 0) DIE("listeners init");

    SSL_CTX* ssl_ctx = init_ssl_ctx();

    if (ssl_ctx == NULL) DIE("ssl_ctx init");

    cxt_t* worker_cxt = malloc(sizeof(cxt_t));
    if (!worker_cxt) DIE("malloc worker_cxt");

    worker_cxt->fdcount = 0;
    worker_cxt->fdsize = INITIAL_FD_SIZE;
    worker_cxt->ssl_ctx = ssl_ctx;

    job_queue_t* queue = malloc(sizeof(job_queue_t));
    if (!queue) DIE("malloc queue");
    queue->head = NULL;
    queue->tail = NULL;
    if (pthread_mutex_init(&queue->lock, NULL) != 0) DIE("mutex init");
    if (pthread_cond_init(&queue->cond, NULL) != 0) DIE("cond init");

    struct pollfd *pfds = calloc(worker_cxt->fdsize, sizeof(struct pollfd));
    if (!pfds) DIE("calloc pfds");

    client_t *clients = calloc(worker_cxt->fdsize, sizeof(client_t));
    if (!clients) DIE("calloc clients");

    pfds[0].fd = listener;
    pfds[0].events = POLLIN;
    worker_cxt->fdcount++;

    pfds[1].fd = ssl_listener;
    pfds[1].events = POLLIN;
    worker_cxt->fdcount++;

    worker_cxt->pfds = pfds;
    if (pthread_mutex_init(&worker_cxt->pfds_lock, NULL) != 0) DIE("pfds_lock init");
    worker_cxt->q = queue;
    worker_cxt->clients = clients;

    worker_cxt->clients[0].fd = listener;
    worker_cxt->clients[0].is_ssl = NOT_TLS;
    worker_cxt->clients[0].ssl = NULL;
    worker_cxt->clients[0].write_buf = NULL;
    worker_cxt->clients[0].write_len = 0;
    worker_cxt->clients[0].write_send = 0;
    
    worker_cxt->clients[1].fd = ssl_listener;
    worker_cxt->clients[1].is_ssl = NOT_TLS;
    worker_cxt->clients[1].ssl = NULL;
    worker_cxt->clients[1].write_buf = NULL;
    worker_cxt->clients[1].write_len = 0;
    worker_cxt->clients[1].write_send = 0;

    printf("server: waiting for connections...\n");

    for (int i = 0; i < WORKER_COUNT; i++) {
        if (pthread_create(&workers[i], NULL, worker_init, (void*) worker_cxt) != 0)
            DIE("pthread_create");
    }

    while (1) {
        int poll_count = poll(worker_cxt->pfds, worker_cxt->fdcount, 100);
        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        process_connections(worker_cxt, listener, ssl_listener);
    }
    end:
    free(worker_cxt->pfds);
    free(worker_cxt->clients);
    free(worker_cxt->q);
    SSL_CTX_free(worker_cxt->ssl_ctx);
    free(worker_cxt);

    return 0;
}
