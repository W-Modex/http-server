#include "net/clients.h"
#include "utils/ctx.h"
#include "worker.h"
#include <pthread.h>

#define WORKER_COUNT 15

pthread_t workers[WORKER_COUNT];

int main(int argc, char** argv) {
    int listener = get_listener_fd("2323");
    int ssl_listener = get_listener_fd("3434");

    if (listener < 0 || ssl_listener < 0) DIE("listeners init");

    cxt_t* ctx = init_ctx(listener, ssl_listener);

    printf("server: waiting for connections...\n");

    for (int i = 0; i < WORKER_COUNT; i++) {
        if (pthread_create(&workers[i], NULL, process_jobs, (void*) ctx) != 0)
            DIE("pthread_create");
    }

    while (1) {
        int poll_count = poll(ctx->pfds, ctx->fdcount, 100);
        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        process_connections(ctx, listener, ssl_listener);
    }

    free(ctx->pfds);
    free(ctx->clients);
    free(ctx->q);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);

    return 0;
}
