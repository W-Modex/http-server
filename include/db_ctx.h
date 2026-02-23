#ifndef DB_CTX_H
#define DB_CTX_H

#include <libpq-fe.h>

void db_ctx_set(PGconn* c);
PGconn* db_ctx_get(void);

#endif
