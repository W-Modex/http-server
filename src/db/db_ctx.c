#include "db_ctx.h"

#include <pthread.h>

static pthread_key_t db_ctx_key;
static pthread_once_t db_ctx_once = PTHREAD_ONCE_INIT;

static void db_ctx_make_key(void) {
    (void)pthread_key_create(&db_ctx_key, NULL);
}

void db_ctx_set(PGconn* c) {
    (void)pthread_once(&db_ctx_once, db_ctx_make_key);
    (void)pthread_setspecific(db_ctx_key, c);
}

PGconn* db_ctx_get(void) {
    (void)pthread_once(&db_ctx_once, db_ctx_make_key);
    return (PGconn*)pthread_getspecific(db_ctx_key);
}
