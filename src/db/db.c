#include "db.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DB_INACTIVITY_TTL_SECONDS (30 * 60)

#define SQLSTATE_UNIQUE_VIOLATION "23505"

enum {
    STMT_USER_CREATE = 0,
    STMT_USER_FIND_LOGIN,
    STMT_SESSION_CREATE,
    STMT_SESSION_GET,
    STMT_SESSION_TOUCH,
    STMT_SESSION_DELETE,
    STMT_SESSION_GC,
    STMT_OAUTH_FIND_USER,
    STMT_OAUTH_UPSERT_LINK,
    STMT_OAUTH_UNLINK,
    STMT_COUNT
};

typedef struct {
    const char* name;
    const char* sql;
} stmt_def_t;

static const stmt_def_t STMT_DEFS[STMT_COUNT] = {
    [STMT_USER_CREATE] = {
        .name = "db_user_create_v1",
        .sql = "INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id"
    },
    [STMT_USER_FIND_LOGIN] = {
        .name = "db_user_find_login_v1",
        .sql = "SELECT id,password_hash FROM users "
               "WHERE email=$1 OR username=$1 "
               "ORDER BY CASE WHEN email=$1 THEN 0 ELSE 1 END, id LIMIT 1"
    },
    [STMT_SESSION_CREATE] = {
        .name = "db_session_create_v1",
        .sql = "INSERT INTO sessions(sid,csrf_secret,uid,created_at,last_seen,expires_at) "
               "VALUES($1,$2,$3,$4,$4,$5)"
    },
    [STMT_SESSION_GET] = {
        .name = "db_session_get_v1",
        .sql = "SELECT uid,csrf_secret,expires_at,last_seen FROM sessions WHERE sid=$1 LIMIT 1"
    },
    [STMT_SESSION_TOUCH] = {
        .name = "db_session_touch_v1",
        .sql = "UPDATE sessions SET last_seen=$2 WHERE sid=$1"
    },
    [STMT_SESSION_DELETE] = {
        .name = "db_session_delete_v1",
        .sql = "DELETE FROM sessions WHERE sid=$1"
    },
    [STMT_SESSION_GC] = {
        .name = "db_session_gc_v1",
        .sql = "DELETE FROM sessions WHERE expires_at <= $1 OR last_seen <= ($1 - $2) OR uid IS NULL"
    },
    [STMT_OAUTH_FIND_USER] = {
        .name = "db_oauth_find_user_v1",
        .sql = "SELECT user_id FROM oauth_identities WHERE provider=$1 AND provider_user_id=$2 LIMIT 1"
    },
    [STMT_OAUTH_UPSERT_LINK] = {
        .name = "db_oauth_upsert_link_v1",
        .sql = "INSERT INTO oauth_identities(provider,provider_user_id,user_id) VALUES($1,$2,$3) "
               "ON CONFLICT(provider,provider_user_id) DO UPDATE SET user_id=EXCLUDED.user_id"
    },
    [STMT_OAUTH_UNLINK] = {
        .name = "db_oauth_unlink_v1",
        .sql = "DELETE FROM oauth_identities WHERE provider=$1 AND provider_user_id=$2"
    }
};

static void db_log_conn_error(const char* where, PGconn* c) {
    if (!where) where = "db";
    const char* msg = c ? PQerrorMessage(c) : "(null connection)";
    fprintf(stderr, "[%s] %s\n", where, msg ? msg : "(no error message)");
}

static void db_log_result_error(const char* where, PGconn* c, PGresult* r) {
    if (!where) where = "db";
    const char* sqlstate = r ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : NULL;
    const char* msg = r ? PQresultErrorMessage(r) : NULL;

    if (msg && *msg) {
        fprintf(stderr, "[%s] sqlstate=%s error=%s", where, sqlstate ? sqlstate : "(none)", msg);
        return;
    }
    db_log_conn_error(where, c);
}

static bool parse_i64_text(const char* s, int64_t* out) {
    if (!s || !*s || !out) return false;
    errno = 0;
    char* end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || (end && *end != '\0')) return false;
    *out = (int64_t)v;
    return true;
}

static bool size_fits_int(size_t n) {
    return n <= (size_t)INT_MAX;
}

static bool copy_string_out(char* out, size_t out_sz, const char* src) {
    if (!out || out_sz == 0 || !src) return false;
    size_t n = strlen(src);
    if (n + 1 > out_sz) return false;
    memcpy(out, src, n + 1);
    return true;
}

static bool cmd_ok(PGresult* r) {
    return r && PQresultStatus(r) == PGRES_COMMAND_OK;
}

static bool tuples_ok(PGresult* r) {
    return r && PQresultStatus(r) == PGRES_TUPLES_OK;
}

static bool exec_simple_cmd(PGconn* c, const char* sql, const char* where) {
    if (!c || !sql) return false;
    PGresult* r = PQexec(c, sql);
    if (!cmd_ok(r)) {
        db_log_result_error(where, c, r);
        PQclear(r);
        return false;
    }
    PQclear(r);
    return true;
}

static bool result_sqlstate_is(PGresult* r, const char* state) {
    if (!r || !state) return false;
    const char* got = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    return got && strcmp(got, state) == 0;
}

static bool parse_cmd_tuples_eq_one(PGresult* r) {
    if (!r || PQresultStatus(r) != PGRES_COMMAND_OK) return false;
    const char* tuples = PQcmdTuples(r);
    return tuples && strcmp(tuples, "1") == 0;
}

PGconn* db_connect(const char* conninfo) {
    if (!conninfo || !*conninfo) return NULL;
    PGconn* c = PQconnectdb(conninfo);
    if (!c || PQstatus(c) != CONNECTION_OK) {
        db_log_conn_error("db_connect", c);
        if (c) PQfinish(c);
        return NULL;
    }
    return c;
}

void db_disconnect(PGconn* c) {
    if (!c) return;
    PQfinish(c);
}

bool db_prepare_all(PGconn* c) {
    if (!c) return false;

    for (size_t i = 0; i < STMT_COUNT; ++i) {
        PGresult* r = PQprepare(c, STMT_DEFS[i].name, STMT_DEFS[i].sql, 0, NULL);
        if (!cmd_ok(r)) {
            db_log_result_error(STMT_DEFS[i].name, c, r);
            PQclear(r);
            return false;
        }
        PQclear(r);
    }

    return true;
}

bool db_begin(PGconn* c) {
    return exec_simple_cmd(c, "BEGIN", "db_begin");
}

bool db_commit(PGconn* c) {
    return exec_simple_cmd(c, "COMMIT", "db_commit");
}

bool db_rollback(PGconn* c) {
    return exec_simple_cmd(c, "ROLLBACK", "db_rollback");
}

bool db_user_create(PGconn* c,
                    const char* username,
                    const char* email,
                    const char* password_hash,
                    int64_t* out_user_id) {
    if (!c || !username || !*username || !email || !*email || !password_hash || !*password_hash || !out_user_id)
        return false;

    const char* values[3] = { username, email, password_hash };
    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_USER_CREATE].name,
                                 3,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!tuples_ok(r)) {
        if (!result_sqlstate_is(r, SQLSTATE_UNIQUE_VIOLATION)) {
            db_log_result_error("db_user_create", c, r);
        }
        PQclear(r);
        return false;
    }

    if (PQntuples(r) != 1 || PQnfields(r) < 1 || PQgetisnull(r, 0, 0)) {
        db_log_result_error("db_user_create:unexpected_result", c, r);
        PQclear(r);
        return false;
    }

    int64_t id = 0;
    if (!parse_i64_text(PQgetvalue(r, 0, 0), &id)) {
        db_log_result_error("db_user_create:bad_id", c, r);
        PQclear(r);
        return false;
    }
    PQclear(r);

    *out_user_id = id;
    return true;
}

bool db_user_find_login(PGconn* c,
                        const char* email_or_username,
                        bool* found,
                        int64_t* out_user_id,
                        char* out_password_hash, size_t out_password_hash_sz) {
    if (!c || !email_or_username || !*email_or_username || !found || !out_user_id ||
        !out_password_hash || out_password_hash_sz == 0) {
        return false;
    }

    *found = false;
    *out_user_id = 0;
    out_password_hash[0] = '\0';

    const char* values[1] = { email_or_username };
    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_USER_FIND_LOGIN].name,
                                 1,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!tuples_ok(r)) {
        db_log_result_error("db_user_find_login", c, r);
        PQclear(r);
        return false;
    }

    int rows = PQntuples(r);
    if (rows == 0) {
        PQclear(r);
        return true;
    }
    if (rows != 1 || PQnfields(r) < 2) {
        db_log_result_error("db_user_find_login:unexpected_result", c, r);
        PQclear(r);
        return false;
    }
    if (PQgetisnull(r, 0, 0) || PQgetisnull(r, 0, 1)) {
        db_log_result_error("db_user_find_login:null_fields", c, r);
        PQclear(r);
        return false;
    }

    int64_t user_id = 0;
    if (!parse_i64_text(PQgetvalue(r, 0, 0), &user_id)) {
        db_log_result_error("db_user_find_login:bad_id", c, r);
        PQclear(r);
        return false;
    }

    const char* pw_hash = PQgetvalue(r, 0, 1);
    if (!copy_string_out(out_password_hash, out_password_hash_sz, pw_hash)) {
        db_log_result_error("db_user_find_login:hash_buffer_too_small", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    *found = true;
    *out_user_id = user_id;
    return true;
}

bool db_session_create(PGconn* c,
                       const uint8_t* sid, size_t sid_len,
                       const uint8_t* csrf_secret, size_t csrf_len,
                       int64_t uid,
                       int64_t created_at,
                       int64_t expires_at) {
    if (!c || !sid || sid_len == 0 || !csrf_secret || csrf_len == 0 || uid <= 0 ||
        created_at <= 0 || expires_at <= 0 || !size_fits_int(sid_len) || !size_fits_int(csrf_len)) {
        return false;
    }

    char uid_buf[32];
    char created_at_buf[32];
    char expires_at_buf[32];

    snprintf(uid_buf, sizeof(uid_buf), "%lld", (long long)uid);
    snprintf(created_at_buf, sizeof(created_at_buf), "%lld", (long long)created_at);
    snprintf(expires_at_buf, sizeof(expires_at_buf), "%lld", (long long)expires_at);

    const char* values[5] = {
        (const char*)sid,
        (const char*)csrf_secret,
        uid_buf,
        created_at_buf,
        expires_at_buf
    };
    int lengths[5] = {
        (int)sid_len,
        (int)csrf_len,
        (int)strlen(uid_buf),
        (int)strlen(created_at_buf),
        (int)strlen(expires_at_buf)
    };
    int formats[5] = { 1, 1, 0, 0, 0 };

    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_SESSION_CREATE].name,
                                 5,
                                 values,
                                 lengths,
                                 formats,
                                 0);
    if (!cmd_ok(r)) {
        db_log_result_error("db_session_create", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}

bool db_session_get_valid(PGconn* c,
                          const uint8_t* sid, size_t sid_len,
                          int64_t now,
                          bool* found,
                          bool* ok,
                          int64_t* out_uid,
                          uint8_t* out_csrf_secret, size_t out_csrf_secret_sz,
                          size_t* out_csrf_secret_len,
                          int64_t* out_expires_at) {
    if (!c || !sid || sid_len == 0 || !size_fits_int(sid_len) || now <= 0 || !found || !ok || !out_uid ||
        !out_csrf_secret || out_csrf_secret_sz == 0 || !out_csrf_secret_len || !out_expires_at) {
        return false;
    }

    *found = false;
    *ok = false;
    *out_uid = 0;
    *out_csrf_secret_len = 0;
    *out_expires_at = 0;

    const char* values[1] = { (const char*)sid };
    int lengths[1] = { (int)sid_len };
    int formats[1] = { 1 };

    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_SESSION_GET].name,
                                 1,
                                 values,
                                 lengths,
                                 formats,
                                 0);
    if (!tuples_ok(r)) {
        db_log_result_error("db_session_get_valid", c, r);
        PQclear(r);
        return false;
    }

    int rows = PQntuples(r);
    if (rows == 0) {
        PQclear(r);
        return true;
    }

    if (rows != 1 || PQnfields(r) < 4) {
        db_log_result_error("db_session_get_valid:unexpected_result", c, r);
        PQclear(r);
        return false;
    }

    *found = true;

    bool uid_is_null = PQgetisnull(r, 0, 0) != 0;
    int64_t uid = 0;
    if (!uid_is_null) {
        if (!parse_i64_text(PQgetvalue(r, 0, 0), &uid)) {
            db_log_result_error("db_session_get_valid:bad_uid", c, r);
            PQclear(r);
            return false;
        }
    }

    if (PQgetisnull(r, 0, 2) || PQgetisnull(r, 0, 3)) {
        db_log_result_error("db_session_get_valid:null_time_fields", c, r);
        PQclear(r);
        return false;
    }

    int64_t expires_at = 0;
    int64_t last_seen = 0;
    if (!parse_i64_text(PQgetvalue(r, 0, 2), &expires_at) ||
        !parse_i64_text(PQgetvalue(r, 0, 3), &last_seen)) {
        db_log_result_error("db_session_get_valid:bad_time_fields", c, r);
        PQclear(r);
        return false;
    }

    *out_uid = uid;
    *out_expires_at = expires_at;

    bool expired = now > expires_at;
    bool inactive = now - last_seen > DB_INACTIVITY_TTL_SECONDS;
    if (uid_is_null || expired || inactive) {
        PQclear(r);
        return true;
    }

    if (PQgetisnull(r, 0, 1)) {
        db_log_result_error("db_session_get_valid:null_csrf", c, r);
        PQclear(r);
        return false;
    }

    size_t decoded_len = 0;
    unsigned char* decoded = PQunescapeBytea((unsigned char*)PQgetvalue(r, 0, 1), &decoded_len);
    if (!decoded) {
        db_log_result_error("db_session_get_valid:bad_csrf_bytea", c, r);
        PQclear(r);
        return false;
    }
    if (decoded_len > out_csrf_secret_sz) {
        db_log_result_error("db_session_get_valid:csrf_buffer_too_small", c, r);
        PQfreemem(decoded);
        PQclear(r);
        return false;
    }

    memcpy(out_csrf_secret, decoded, decoded_len);
    *out_csrf_secret_len = decoded_len;
    PQfreemem(decoded);
    *ok = true;

    PQclear(r);
    return true;
}

bool db_session_touch(PGconn* c,
                      const uint8_t* sid, size_t sid_len,
                      int64_t last_seen) {
    if (!c || !sid || sid_len == 0 || last_seen <= 0 || !size_fits_int(sid_len)) return false;

    char last_seen_buf[32];
    snprintf(last_seen_buf, sizeof(last_seen_buf), "%lld", (long long)last_seen);

    const char* values[2] = {
        (const char*)sid,
        last_seen_buf
    };
    int lengths[2] = {
        (int)sid_len,
        (int)strlen(last_seen_buf)
    };
    int formats[2] = { 1, 0 };

    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_SESSION_TOUCH].name,
                                 2,
                                 values,
                                 lengths,
                                 formats,
                                 0);
    if (!parse_cmd_tuples_eq_one(r)) {
        if (r && PQresultStatus(r) != PGRES_COMMAND_OK) {
            db_log_result_error("db_session_touch", c, r);
        }
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}

bool db_session_delete(PGconn* c,
                       const uint8_t* sid, size_t sid_len) {
    if (!c || !sid || sid_len == 0 || !size_fits_int(sid_len)) return false;

    const char* values[1] = { (const char*)sid };
    int lengths[1] = { (int)sid_len };
    int formats[1] = { 1 };

    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_SESSION_DELETE].name,
                                 1,
                                 values,
                                 lengths,
                                 formats,
                                 0);
    if (!parse_cmd_tuples_eq_one(r)) {
        if (r && PQresultStatus(r) != PGRES_COMMAND_OK) {
            db_log_result_error("db_session_delete", c, r);
        }
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}

bool db_session_gc_expired(PGconn* c, int64_t now) {
    if (!c || now <= 0) return false;

    char now_buf[32];
    char inactivity_buf[32];
    snprintf(now_buf, sizeof(now_buf), "%lld", (long long)now);
    snprintf(inactivity_buf, sizeof(inactivity_buf), "%d", DB_INACTIVITY_TTL_SECONDS);

    const char* values[2] = {
        now_buf,
        inactivity_buf
    };

    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_SESSION_GC].name,
                                 2,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!cmd_ok(r)) {
        db_log_result_error("db_session_gc_expired", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}

bool db_oauth_find_user(PGconn* c,
                        const char* provider,
                        const char* provider_user_id,
                        bool* found,
                        int64_t* out_user_id) {
    if (!c || !provider || !*provider || !provider_user_id || !*provider_user_id ||
        !found || !out_user_id) {
        return false;
    }

    *found = false;
    *out_user_id = 0;

    const char* values[2] = { provider, provider_user_id };
    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_OAUTH_FIND_USER].name,
                                 2,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!tuples_ok(r)) {
        db_log_result_error("db_oauth_find_user", c, r);
        PQclear(r);
        return false;
    }

    int rows = PQntuples(r);
    if (rows == 0) {
        PQclear(r);
        return true;
    }

    if (rows != 1 || PQnfields(r) < 1 || PQgetisnull(r, 0, 0)) {
        db_log_result_error("db_oauth_find_user:unexpected_result", c, r);
        PQclear(r);
        return false;
    }

    int64_t user_id = 0;
    if (!parse_i64_text(PQgetvalue(r, 0, 0), &user_id)) {
        db_log_result_error("db_oauth_find_user:bad_user_id", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    *found = true;
    *out_user_id = user_id;
    return true;
}

bool db_oauth_upsert_link(PGconn* c,
                          const char* provider,
                          const char* provider_user_id,
                          int64_t user_id) {
    if (!c || !provider || !*provider || !provider_user_id || !*provider_user_id || user_id <= 0)
        return false;

    char user_id_buf[32];
    snprintf(user_id_buf, sizeof(user_id_buf), "%lld", (long long)user_id);

    const char* values[3] = { provider, provider_user_id, user_id_buf };
    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_OAUTH_UPSERT_LINK].name,
                                 3,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!cmd_ok(r)) {
        db_log_result_error("db_oauth_upsert_link", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}

bool db_oauth_unlink(PGconn* c,
                     const char* provider,
                     const char* provider_user_id) {
    if (!c || !provider || !*provider || !provider_user_id || !*provider_user_id)
        return false;

    const char* values[2] = { provider, provider_user_id };
    PGresult* r = PQexecPrepared(c,
                                 STMT_DEFS[STMT_OAUTH_UNLINK].name,
                                 2,
                                 values,
                                 NULL,
                                 NULL,
                                 0);
    if (!cmd_ok(r)) {
        db_log_result_error("db_oauth_unlink", c, r);
        PQclear(r);
        return false;
    }

    PQclear(r);
    return true;
}
