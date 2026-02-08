#include "net/clients.h"
#include "utils/ctx.h"
#include "worker.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#define WORKER_COUNT 7

pthread_t workers[WORKER_COUNT];

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    int listener = get_listener_fd("2323");
    int ssl_listener = get_listener_fd("3434");

    if (listener < 0 || ssl_listener < 0) DIE("listeners init");

    cxt_t* ctx = init_ctx(listener, ssl_listener);
    fprintf(stderr, "Using STATIC_DIR: %s\n", STATIC_DIR);
    printf("server: waiting for connections...\n");

    for (int i = 0; i < WORKER_COUNT; i++) {
        if (pthread_create(&workers[i], NULL, process_jobs, (void*) ctx) != 0)
            DIE("pthread_create");
    }

    while (1) {
        struct pollfd *pfds_snapshot = NULL;
        int fdcount_snapshot = 0;

        pthread_mutex_lock(&ctx->pfds_lock);
        fdcount_snapshot = ctx->fdcount;
        if (fdcount_snapshot > 0) {
            pfds_snapshot = malloc(sizeof(struct pollfd) * fdcount_snapshot);
            if (pfds_snapshot) {
                memcpy(pfds_snapshot, ctx->pfds, sizeof(struct pollfd) * fdcount_snapshot);
            }
        }
        pthread_mutex_unlock(&ctx->pfds_lock);

        if (!pfds_snapshot) {
            continue;
        }

        int poll_count = poll(pfds_snapshot, fdcount_snapshot, 100);
        if (poll_count == -1) DIE("poll");
        process_connections(ctx, listener, ssl_listener, pfds_snapshot, fdcount_snapshot);
        free(pfds_snapshot);
    }

    free(ctx->pfds);
    free(ctx->clients);
    free(ctx->q);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);

    return 0;
}
