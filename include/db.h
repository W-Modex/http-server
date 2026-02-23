#ifndef DB_H 
#define DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libpq-fe.h>

PGconn* db_connect(const char* conninfo);
void    db_disconnect(PGconn* c);

bool db_prepare_all(PGconn* c);

bool db_begin(PGconn* c);
bool db_commit(PGconn* c);
bool db_rollback(PGconn* c);

bool db_user_create(PGconn* c,
                    const char* username,
                    const char* email,
                    const char* password_hash,
                    int64_t* out_user_id);

bool db_user_find_login(PGconn* c,
                        const char* email_or_username,
                        bool* found,
                        int64_t* out_user_id,
                        char* out_password_hash, size_t out_password_hash_sz);

bool db_session_create(PGconn* c,
                       const uint8_t* sid, size_t sid_len,
                       const uint8_t* csrf_secret, size_t csrf_len,
                       int64_t uid,
                       int64_t created_at,
                       int64_t expires_at);

bool db_session_get_valid(PGconn* c,
                          const uint8_t* sid, size_t sid_len,
                          int64_t now,
                          bool* found,
                          bool* ok,
                          int64_t* out_uid,
                          uint8_t* out_csrf_secret, size_t out_csrf_secret_sz,
                          size_t* out_csrf_secret_len,
                          int64_t* out_expires_at);

bool db_session_touch(PGconn* c,
                      const uint8_t* sid, size_t sid_len,
                      int64_t last_seen);

bool db_session_delete(PGconn* c,
                       const uint8_t* sid, size_t sid_len);

bool db_session_gc_expired(PGconn* c, int64_t now);

bool db_oauth_find_user(PGconn* c,
                        const char* provider,
                        const char* provider_user_id,
                        bool* found,
                        int64_t* out_user_id);

bool db_oauth_upsert_link(PGconn* c,
                          const char* provider,
                          const char* provider_user_id,
                          int64_t user_id);

bool db_oauth_unlink(PGconn* c,
                     const char* provider,
                     const char* provider_user_id);


#endif