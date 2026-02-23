#include "db.h"
#include "db_ctx.h"
#include "auth/oauth.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define INACTIVITY_TTL_SECONDS (30 * 60)

typedef int (*test_fn_t)(void);

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
            return 1; \
        } \
    } while (0)

static PGconn* g_conn = NULL;
static char g_schema[128] = {0};

static int parse_i64(const char* s, int64_t* out) {
    if (!s || !*s || !out) return 0;
    errno = 0;
    char* end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || (end && *end != '\0')) return 0;
    *out = (int64_t)v;
    return 1;
}

static int exec_sql(const char* sql) {
    if (!g_conn || !sql) return 0;
    PGresult* r = PQexec(g_conn, sql);
    if (!r) return 0;
    ExecStatusType st = PQresultStatus(r);
    int ok = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!ok) {
        printf("SQL failed: %s\n", sql);
        printf("  error: %s\n", PQresultErrorMessage(r));
    }
    PQclear(r);
    return ok;
}

static void fill_bytes(uint8_t* out, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(seed + i);
}

static int insert_raw_session(const uint8_t* sid, size_t sid_len,
                              const uint8_t* csrf, size_t csrf_len,
                              int uid_is_null,
                              int64_t uid,
                              int64_t created_at,
                              int64_t last_seen,
                              int64_t expires_at) {
    if (!g_conn || !sid || !csrf || sid_len == 0 || csrf_len == 0) return 0;

    char uid_buf[32];
    char created_buf[32];
    char last_seen_buf[32];
    char expires_buf[32];

    snprintf(uid_buf, sizeof(uid_buf), "%lld", (long long)uid);
    snprintf(created_buf, sizeof(created_buf), "%lld", (long long)created_at);
    snprintf(last_seen_buf, sizeof(last_seen_buf), "%lld", (long long)last_seen);
    snprintf(expires_buf, sizeof(expires_buf), "%lld", (long long)expires_at);

    const char* values[6] = {
        (const char*)sid,
        (const char*)csrf,
        uid_is_null ? NULL : uid_buf,
        created_buf,
        last_seen_buf,
        expires_buf
    };

    int lengths[6] = {
        (int)sid_len,
        (int)csrf_len,
        uid_is_null ? 0 : (int)strlen(uid_buf),
        (int)strlen(created_buf),
        (int)strlen(last_seen_buf),
        (int)strlen(expires_buf)
    };

    int formats[6] = { 1, 1, 0, 0, 0, 0 };

    PGresult* r = PQexecParams(
        g_conn,
        "INSERT INTO sessions(sid,csrf_secret,uid,created_at,last_seen,expires_at) VALUES($1,$2,$3,$4,$5,$6)",
        6,
        NULL,
        values,
        lengths,
        formats,
        0
    );

    if (!r) return 0;
    int ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
    if (!ok) {
        printf("insert_raw_session failed: %s\n", PQresultErrorMessage(r));
    }
    PQclear(r);
    return ok;
}

static int session_exists(const uint8_t* sid, size_t sid_len, int* out_exists) {
    if (!g_conn || !sid || sid_len == 0 || !out_exists) return 0;

    const char* values[1] = { (const char*)sid };
    int lengths[1] = { (int)sid_len };
    int formats[1] = { 1 };

    PGresult* r = PQexecParams(
        g_conn,
        "SELECT 1 FROM sessions WHERE sid=$1 LIMIT 1",
        1,
        NULL,
        values,
        lengths,
        formats,
        0
    );

    if (!r) return 0;
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        PQclear(r);
        return 0;
    }

    *out_exists = (PQntuples(r) == 1);
    PQclear(r);
    return 1;
}

static int get_username_by_uid(uint64_t uid, char* out, size_t out_sz) {
    if (!g_conn || uid == 0 || !out || out_sz == 0) return 0;
    out[0] = '\0';

    char uid_buf[32];
    snprintf(uid_buf, sizeof(uid_buf), "%llu", (unsigned long long)uid);
    const char* values[1] = { uid_buf };

    PGresult* r = PQexecParams(
        g_conn,
        "SELECT username FROM users WHERE id=$1 LIMIT 1",
        1,
        NULL,
        values,
        NULL,
        NULL,
        0
    );

    if (!r) return 0;
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1 || PQgetisnull(r, 0, 0)) {
        PQclear(r);
        return 0;
    }

    const char* username = PQgetvalue(r, 0, 0);
    size_t n = strlen(username);
    if (n + 1 > out_sz) {
        PQclear(r);
        return 0;
    }
    memcpy(out, username, n + 1);
    PQclear(r);
    return 1;
}

static int get_last_seen(const uint8_t* sid, size_t sid_len, int64_t* out_last_seen) {
    if (!g_conn || !sid || sid_len == 0 || !out_last_seen) return 0;

    const char* values[1] = { (const char*)sid };
    int lengths[1] = { (int)sid_len };
    int formats[1] = { 1 };

    PGresult* r = PQexecParams(
        g_conn,
        "SELECT last_seen FROM sessions WHERE sid=$1 LIMIT 1",
        1,
        NULL,
        values,
        lengths,
        formats,
        0
    );

    if (!r) return 0;
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1 || PQgetisnull(r, 0, 0)) {
        PQclear(r);
        return 0;
    }

    int ok = parse_i64(PQgetvalue(r, 0, 0), out_last_seen);
    PQclear(r);
    return ok;
}

static int setup_db(void) {
    const char* conninfo = getenv("DATABASE_URL");
    if (!conninfo || !*conninfo) {
        printf("test_db skipped: DATABASE_URL not set\n");
        return 77;
    }

    g_conn = db_connect(conninfo);
    if (!g_conn) {
        printf("test_db failed: could not connect using DATABASE_URL\n");
        return 1;
    }

    snprintf(g_schema, sizeof(g_schema), "test_db_%lld_%d",
             (long long)time(NULL), (int)getpid());

    char sql[512];
    snprintf(sql, sizeof(sql), "CREATE SCHEMA %s", g_schema);
    if (!exec_sql(sql)) return 1;

    snprintf(sql, sizeof(sql), "SET search_path TO %s", g_schema);
    if (!exec_sql(sql)) return 1;

    if (!exec_sql("CREATE TABLE users ("
                  "id BIGSERIAL PRIMARY KEY,"
                  "username TEXT NOT NULL UNIQUE,"
                  "email TEXT NOT NULL UNIQUE,"
                  "password_hash TEXT NOT NULL"
                  ")")) return 1;

    if (!exec_sql("CREATE TABLE sessions ("
                  "sid BYTEA PRIMARY KEY,"
                  "csrf_secret BYTEA NOT NULL,"
                  "uid BIGINT REFERENCES users(id) ON DELETE SET NULL,"
                  "created_at BIGINT NOT NULL,"
                  "last_seen BIGINT NOT NULL,"
                  "expires_at BIGINT NOT NULL"
                  ")")) return 1;

    if (!exec_sql("CREATE INDEX sessions_uid_idx ON sessions(uid)")) return 1;
    if (!exec_sql("CREATE INDEX sessions_expires_at_idx ON sessions(expires_at)")) return 1;

    if (!exec_sql("CREATE TABLE oauth_identities ("
                  "provider TEXT NOT NULL,"
                  "provider_user_id TEXT NOT NULL,"
                  "user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
                  "PRIMARY KEY(provider, provider_user_id)"
                  ")")) return 1;

    if (!exec_sql("CREATE INDEX oauth_identities_user_id_idx ON oauth_identities(user_id)")) return 1;

    if (!db_prepare_all(g_conn)) {
        printf("db_prepare_all failed\n");
        return 1;
    }

    db_ctx_set(g_conn);
    return 0;
}

static void teardown_db(void) {
    if (!g_conn) return;

    if (g_schema[0]) {
        char sql[512];
        snprintf(sql, sizeof(sql), "DROP SCHEMA IF EXISTS %s CASCADE", g_schema);
        (void)exec_sql(sql);
    }

    db_disconnect(g_conn);
    g_conn = NULL;
}

static int test_connect_prepare_and_txn(void) {
    ASSERT_TRUE(g_conn != NULL);
    ASSERT_TRUE(db_begin(g_conn));
    ASSERT_TRUE(db_commit(g_conn));
    ASSERT_TRUE(db_begin(g_conn));
    ASSERT_TRUE(db_rollback(g_conn));
    return 0;
}

static int test_invalid_connection_string(void) {
    PGconn* bad = db_connect("host=127.0.0.1 port=1 dbname=postgres connect_timeout=1");
    ASSERT_TRUE(bad == NULL);
    return 0;
}

static int test_user_create_and_find_login(void) {
    int64_t uid1 = 0;
    int64_t uid2 = 0;
    int64_t uid3 = 0;

    ASSERT_TRUE(db_user_create(g_conn, "alpha", "shared@example.com", "hash_alpha", &uid1));
    ASSERT_TRUE(uid1 > 0);

    ASSERT_TRUE(!db_user_create(g_conn, "alpha", "alpha2@example.com", "hash_dup", &uid2));

    ASSERT_TRUE(db_user_create(g_conn, "bravo", "other@example.com", "hash_bravo", &uid2));
    ASSERT_TRUE(uid2 > uid1);

    ASSERT_TRUE(db_user_create(g_conn, "shared@example.com", "third@example.com", "hash_shared_username", &uid3));
    ASSERT_TRUE(uid3 > uid2);

    bool found = false;
    int64_t out_uid = 0;
    char out_hash[128];

    ASSERT_TRUE(db_user_find_login(g_conn, "missing@example.com", &found, &out_uid, out_hash, sizeof(out_hash)));
    ASSERT_TRUE(found == false);

    ASSERT_TRUE(db_user_find_login(g_conn, "alpha", &found, &out_uid, out_hash, sizeof(out_hash)));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(out_uid == uid1);
    ASSERT_TRUE(strcmp(out_hash, "hash_alpha") == 0);

    ASSERT_TRUE(db_user_find_login(g_conn, "shared@example.com", &found, &out_uid, out_hash, sizeof(out_hash)));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(out_uid == uid1);
    ASSERT_TRUE(strcmp(out_hash, "hash_alpha") == 0);

    ASSERT_TRUE(!db_user_find_login(g_conn, "alpha", &found, &out_uid, out_hash, 2));

    return 0;
}

static int test_session_create_and_get_valid(void) {
    int64_t uid = 0;
    ASSERT_TRUE(db_user_create(g_conn, "session_user", "session_user@example.com", "pw_hash", &uid));

    uint8_t sid[32];
    uint8_t csrf[32];
    fill_bytes(sid, sizeof(sid), 0x10);
    fill_bytes(csrf, sizeof(csrf), 0x50);

    int64_t now = (int64_t)time(NULL);

    ASSERT_TRUE(db_session_create(g_conn, sid, sizeof(sid), csrf, sizeof(csrf), uid, now, now + 3600));
    ASSERT_TRUE(!db_session_create(g_conn, sid, sizeof(sid), csrf, sizeof(csrf), 0, now, now + 3600));

    bool found = false;
    bool ok = false;
    int64_t out_uid = 0;
    uint8_t out_csrf[64] = {0};
    size_t out_csrf_len = 0;
    int64_t out_expires = 0;

    ASSERT_TRUE(db_session_get_valid(g_conn,
                                     sid,
                                     sizeof(sid),
                                     now + 5,
                                     &found,
                                     &ok,
                                     &out_uid,
                                     out_csrf,
                                     sizeof(out_csrf),
                                     &out_csrf_len,
                                     &out_expires));

    ASSERT_TRUE(found == true);
    ASSERT_TRUE(ok == true);
    ASSERT_TRUE(out_uid == uid);
    ASSERT_TRUE(out_csrf_len == sizeof(csrf));
    ASSERT_TRUE(memcmp(out_csrf, csrf, sizeof(csrf)) == 0);
    ASSERT_TRUE(out_expires == now + 3600);

    uint8_t missing_sid[32];
    fill_bytes(missing_sid, sizeof(missing_sid), 0x99);

    ASSERT_TRUE(db_session_get_valid(g_conn,
                                     missing_sid,
                                     sizeof(missing_sid),
                                     now,
                                     &found,
                                     &ok,
                                     &out_uid,
                                     out_csrf,
                                     sizeof(out_csrf),
                                     &out_csrf_len,
                                     &out_expires));
    ASSERT_TRUE(found == false);
    ASSERT_TRUE(ok == false);

    return 0;
}

static int test_session_invalid_states(void) {
    int64_t uid = 0;
    ASSERT_TRUE(db_user_create(g_conn, "invalid_state_user", "invalid_state_user@example.com", "pw_hash", &uid));

    int64_t now = (int64_t)time(NULL);

    uint8_t sid_expired[32];
    uint8_t sid_inactive[32];
    uint8_t sid_null_uid[32];
    uint8_t csrf[32];
    fill_bytes(sid_expired, sizeof(sid_expired), 0x21);
    fill_bytes(sid_inactive, sizeof(sid_inactive), 0x31);
    fill_bytes(sid_null_uid, sizeof(sid_null_uid), 0x41);
    fill_bytes(csrf, sizeof(csrf), 0x61);

    ASSERT_TRUE(db_session_create(g_conn, sid_expired, sizeof(sid_expired), csrf, sizeof(csrf), uid, now - 200, now - 1));
    ASSERT_TRUE(db_session_create(g_conn,
                                  sid_inactive,
                                  sizeof(sid_inactive),
                                  csrf,
                                  sizeof(csrf),
                                  uid,
                                  now - (INACTIVITY_TTL_SECONDS + 10),
                                  now + 7200));

    ASSERT_TRUE(insert_raw_session(sid_null_uid,
                                   sizeof(sid_null_uid),
                                   csrf,
                                   sizeof(csrf),
                                   1,
                                   0,
                                   now,
                                   now,
                                   now + 7200));

    bool found = false;
    bool ok = false;
    int64_t out_uid = 0;
    uint8_t out_csrf[64] = {0};
    size_t out_csrf_len = 0;
    int64_t out_expires = 0;

    ASSERT_TRUE(db_session_get_valid(g_conn,
                                     sid_expired,
                                     sizeof(sid_expired),
                                     now,
                                     &found,
                                     &ok,
                                     &out_uid,
                                     out_csrf,
                                     sizeof(out_csrf),
                                     &out_csrf_len,
                                     &out_expires));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(ok == false);

    ASSERT_TRUE(db_session_get_valid(g_conn,
                                     sid_inactive,
                                     sizeof(sid_inactive),
                                     now,
                                     &found,
                                     &ok,
                                     &out_uid,
                                     out_csrf,
                                     sizeof(out_csrf),
                                     &out_csrf_len,
                                     &out_expires));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(ok == false);

    ASSERT_TRUE(db_session_get_valid(g_conn,
                                     sid_null_uid,
                                     sizeof(sid_null_uid),
                                     now,
                                     &found,
                                     &ok,
                                     &out_uid,
                                     out_csrf,
                                     sizeof(out_csrf),
                                     &out_csrf_len,
                                     &out_expires));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(ok == false);

    return 0;
}

static int test_session_touch_delete_and_gc(void) {
    int64_t uid = 0;
    ASSERT_TRUE(db_user_create(g_conn, "touch_user", "touch_user@example.com", "pw_hash", &uid));

    int64_t now = (int64_t)time(NULL);

    uint8_t sid_touch[32];
    uint8_t sid_delete[32];
    uint8_t sid_gc_keep[32];
    uint8_t sid_gc_expired[32];
    uint8_t sid_gc_inactive[32];
    uint8_t sid_gc_null_uid[32];
    uint8_t csrf[32];

    fill_bytes(sid_touch, sizeof(sid_touch), 0x70);
    fill_bytes(sid_delete, sizeof(sid_delete), 0x80);
    fill_bytes(sid_gc_keep, sizeof(sid_gc_keep), 0x90);
    fill_bytes(sid_gc_expired, sizeof(sid_gc_expired), 0xA0);
    fill_bytes(sid_gc_inactive, sizeof(sid_gc_inactive), 0xB0);
    fill_bytes(sid_gc_null_uid, sizeof(sid_gc_null_uid), 0xC0);
    fill_bytes(csrf, sizeof(csrf), 0xD0);

    ASSERT_TRUE(db_session_create(g_conn, sid_touch, sizeof(sid_touch), csrf, sizeof(csrf), uid, now, now + 3600));
    ASSERT_TRUE(db_session_create(g_conn, sid_delete, sizeof(sid_delete), csrf, sizeof(csrf), uid, now, now + 3600));

    ASSERT_TRUE(db_session_touch(g_conn, sid_touch, sizeof(sid_touch), now + 123));
    int64_t actual_last_seen = 0;
    ASSERT_TRUE(get_last_seen(sid_touch, sizeof(sid_touch), &actual_last_seen));
    ASSERT_TRUE(actual_last_seen == now + 123);

    uint8_t sid_missing[32];
    fill_bytes(sid_missing, sizeof(sid_missing), 0xEE);
    ASSERT_TRUE(!db_session_touch(g_conn, sid_missing, sizeof(sid_missing), now + 1));

    ASSERT_TRUE(db_session_delete(g_conn, sid_delete, sizeof(sid_delete)));
    ASSERT_TRUE(!db_session_delete(g_conn, sid_delete, sizeof(sid_delete)));

    ASSERT_TRUE(db_session_create(g_conn, sid_gc_keep, sizeof(sid_gc_keep), csrf, sizeof(csrf), uid, now, now + 7200));
    ASSERT_TRUE(db_session_create(g_conn, sid_gc_expired, sizeof(sid_gc_expired), csrf, sizeof(csrf), uid, now - 100, now - 1));
    ASSERT_TRUE(db_session_create(g_conn,
                                  sid_gc_inactive,
                                  sizeof(sid_gc_inactive),
                                  csrf,
                                  sizeof(csrf),
                                  uid,
                                  now - (INACTIVITY_TTL_SECONDS + 5),
                                  now + 7200));
    ASSERT_TRUE(insert_raw_session(sid_gc_null_uid,
                                   sizeof(sid_gc_null_uid),
                                   csrf,
                                   sizeof(csrf),
                                   1,
                                   0,
                                   now,
                                   now,
                                   now + 7200));

    ASSERT_TRUE(db_session_gc_expired(g_conn, now));

    int exists_keep = 0;
    int exists_expired = 0;
    int exists_inactive = 0;
    int exists_null_uid = 0;

    ASSERT_TRUE(session_exists(sid_gc_keep, sizeof(sid_gc_keep), &exists_keep));
    ASSERT_TRUE(session_exists(sid_gc_expired, sizeof(sid_gc_expired), &exists_expired));
    ASSERT_TRUE(session_exists(sid_gc_inactive, sizeof(sid_gc_inactive), &exists_inactive));
    ASSERT_TRUE(session_exists(sid_gc_null_uid, sizeof(sid_gc_null_uid), &exists_null_uid));

    ASSERT_TRUE(exists_keep == 1);
    ASSERT_TRUE(exists_expired == 0);
    ASSERT_TRUE(exists_inactive == 0);
    ASSERT_TRUE(exists_null_uid == 0);

    ASSERT_TRUE(!db_session_gc_expired(g_conn, 0));

    return 0;
}

static int test_oauth_find_upsert_unlink(void) {
    int64_t uid1 = 0;
    int64_t uid2 = 0;

    ASSERT_TRUE(db_user_create(g_conn, "oauth_user1", "oauth_user1@example.com", "pw_hash", &uid1));
    ASSERT_TRUE(db_user_create(g_conn, "oauth_user2", "oauth_user2@example.com", "pw_hash", &uid2));

    bool found = false;
    int64_t out_uid = 0;

    ASSERT_TRUE(db_oauth_find_user(g_conn, "Google", "google-sub-1", &found, &out_uid));
    ASSERT_TRUE(found == false);

    ASSERT_TRUE(db_oauth_upsert_link(g_conn, "Google", "google-sub-1", uid1));
    ASSERT_TRUE(db_oauth_find_user(g_conn, "Google", "google-sub-1", &found, &out_uid));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(out_uid == uid1);

    ASSERT_TRUE(db_oauth_upsert_link(g_conn, "Google", "google-sub-1", uid2));
    ASSERT_TRUE(db_oauth_find_user(g_conn, "Google", "google-sub-1", &found, &out_uid));
    ASSERT_TRUE(found == true);
    ASSERT_TRUE(out_uid == uid2);

    ASSERT_TRUE(db_oauth_unlink(g_conn, "Google", "google-sub-1"));
    ASSERT_TRUE(db_oauth_find_user(g_conn, "Google", "google-sub-1", &found, &out_uid));
    ASSERT_TRUE(found == false);

    ASSERT_TRUE(db_oauth_unlink(g_conn, "Google", "google-sub-1"));

    return 0;
}

static int test_oauth_find_or_create_user_db_backed(void) {
    uint64_t uid1 = oauth_find_or_create_user("Google", "google-sub-a1", "alice.one@example.com", "Alice");
    uint64_t uid2 = oauth_find_or_create_user("Google", "google-sub-a2", "alice.two@example.com", "Alice");
    uint64_t uid3 = oauth_find_or_create_user("Google", "google-sub-a3", "alice.three@example.com", "Alice");
    uint64_t uid4 = oauth_find_or_create_user("Google", "google-sub-b1", "bob.smith@example.com", NULL);
    uint64_t uid1_again = oauth_find_or_create_user("Google", "google-sub-a1", "ignored@example.com", "Other");

    ASSERT_TRUE(uid1 > 0);
    ASSERT_TRUE(uid2 > 0);
    ASSERT_TRUE(uid3 > 0);
    ASSERT_TRUE(uid4 > 0);
    ASSERT_TRUE(uid1_again == uid1);

    char uname1[128];
    char uname2[128];
    char uname3[128];
    char uname4[128];

    ASSERT_TRUE(get_username_by_uid(uid1, uname1, sizeof(uname1)));
    ASSERT_TRUE(get_username_by_uid(uid2, uname2, sizeof(uname2)));
    ASSERT_TRUE(get_username_by_uid(uid3, uname3, sizeof(uname3)));
    ASSERT_TRUE(get_username_by_uid(uid4, uname4, sizeof(uname4)));

    ASSERT_TRUE(strcmp(uname1, "alice") == 0);
    ASSERT_TRUE(strcmp(uname2, "alice_2") == 0);
    ASSERT_TRUE(strcmp(uname3, "alice_3") == 0);
    ASSERT_TRUE(strcmp(uname4, "bob.smith") == 0);

    return 0;
}

int main(void) {
    int setup_status = setup_db();
    if (setup_status == 77) return 0;
    if (setup_status != 0) {
        teardown_db();
        return 1;
    }

    test_fn_t tests[] = {
        test_connect_prepare_and_txn,
        test_invalid_connection_string,
        test_user_create_and_find_login,
        test_session_create_and_get_valid,
        test_session_invalid_states,
        test_session_touch_delete_and_gc,
        test_oauth_find_upsert_unlink,
        test_oauth_find_or_create_user_db_backed,
    };

    const size_t test_count = sizeof(tests) / sizeof(tests[0]);
    int failures = 0;

    for (size_t i = 0; i < test_count; ++i) {
        failures += tests[i]();
    }

    teardown_db();

    if (failures == 0) {
        printf("test_db passed!\n");
        return 0;
    }

    printf("test_db had %d failure(s)\n", failures);
    return 1;
}
