#include "auth/session.h"

#include "auth/cookie.h"
#include "auth/crypto.h"
#include "db.h"
#include "db_ctx.h"
#include "http/body.h"
#include "http/request.h"
#include "http/response.h"
#include "utils/str.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static s_list_t anon_session_store = {
    .count = 0,
    .s_lock = PTHREAD_MUTEX_INITIALIZER
};

static size_t sid_hash(const unsigned char *sid) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < SESSION_ID_LEN; ++i) {
        h ^= (uint64_t)sid[i];
        h *= 1099511628211ULL;
    }
    return (size_t)(h % MAX_SESSION_BUCKET);
}

static session_t *anon_session_find_locked(const unsigned char *sid, size_t *bucket_out, session_t **prev_out) {
    if (!sid) return NULL;
    size_t bucket = sid_hash(sid);
    if (bucket_out) *bucket_out = bucket;

    session_t *prev = NULL;
    session_t *cur = anon_session_store.buckets[bucket];
    while (cur) {
        if (memcmp(cur->sid, sid, SESSION_ID_LEN) == 0) {
            if (prev_out) *prev_out = prev;
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }

    if (prev_out) *prev_out = NULL;
    return NULL;
}

static int anon_bucket_has_sid_locked(size_t bucket, const unsigned char *sid) {
    session_t *cur = anon_session_store.buckets[bucket];
    while (cur) {
        if (memcmp(cur->sid, sid, SESSION_ID_LEN) == 0) return 1;
        cur = cur->next;
    }
    return 0;
}

static void anon_unlink_session_locked(size_t bucket, session_t *prev, session_t *cur) {
    if (!cur) return;
    if (prev) prev->next = cur->next;
    else anon_session_store.buckets[bucket] = cur->next;
    cur->next = NULL;
    if (anon_session_store.count > 0) anon_session_store.count--;
}

static int session_expired(const session_t *session, uint64_t now) {
    if (!session) return 1;
    if (session->expires_at == 0) return 0;
    return (now > session->expires_at) || (now - session->last_seen > SESSION_INACTIVITY_TTL);
}

static PGconn* auth_db(void) {
    return db_ctx_get();
}

static int db_user_exists(PGconn *db, uint64_t uid) {
    if (!db || uid == 0) return 0;

    char uid_buf[32];
    snprintf(uid_buf, sizeof(uid_buf), "%llu", (unsigned long long)uid);
    const char *values[1] = { uid_buf };

    PGresult *r = PQexecParams(db,
                               "SELECT 1 FROM users WHERE id=$1 LIMIT 1",
                               1,
                               NULL,
                               values,
                               NULL,
                               NULL,
                               0);
    if (!r) return 0;

    int ok = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1);
    PQclear(r);
    return ok;
}

int get_username_by_id(uint64_t uid, char *out, size_t out_sz) {
    if (!out || out_sz == 0 || uid == 0) return 0;
    out[0] = '\0';

    PGconn *db = auth_db();
    if (!db) return 0;

    char uid_buf[32];
    snprintf(uid_buf, sizeof(uid_buf), "%llu", (unsigned long long)uid);
    const char *values[1] = { uid_buf };

    PGresult *r = PQexecParams(db,
                               "SELECT username FROM users WHERE id=$1 LIMIT 1",
                               1,
                               NULL,
                               values,
                               NULL,
                               NULL,
                               0);
    if (!r) return 0;
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1 || PQgetisnull(r, 0, 0)) {
        PQclear(r);
        return 0;
    }

    const char *username = PQgetvalue(r, 0, 0);
    size_t n = strlen(username);
    if (n + 1 > out_sz) {
        PQclear(r);
        return 0;
    }

    memcpy(out, username, n + 1);
    PQclear(r);
    return 1;
}

static int create_anonymous_session_internal(http_request_t *req) {
    if (!req) return 0;

    session_t session = {0};
    if (rand_bytes(session.csrf_secret, SESSION_CSRF_LEN) != 0) return 0;

    uint64_t now = (uint64_t)time(NULL);
    session.uid = 0;
    session.created_at = now;
    session.last_seen = now;
    session.expires_at = now + SESSION_TTL;
    session.next = NULL;

    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(session.sid, SESSION_ID_LEN) != 0) return 0;

        pthread_mutex_lock(&anon_session_store.s_lock);
        if (anon_session_store.count >= MAX_SESSION_SIZE) {
            pthread_mutex_unlock(&anon_session_store.s_lock);
            return 0;
        }

        if (!anon_session_find_locked(session.sid, NULL, NULL)) {
            session_t *node = malloc(sizeof(*node));
            if (!node) {
                pthread_mutex_unlock(&anon_session_store.s_lock);
                return 0;
            }
            *node = session;

            size_t bucket = sid_hash(session.sid);
            node->next = anon_session_store.buckets[bucket];
            anon_session_store.buckets[bucket] = node;
            anon_session_store.count++;

            pthread_mutex_unlock(&anon_session_store.s_lock);
            req->session = session;
            return 1;
        }

        pthread_mutex_unlock(&anon_session_store.s_lock);
    }

    return 0;
}

int create_session(http_request_t *req, uint64_t uid) {
    if (!req) return 0;
    if (uid == 0) return create_anonymous_session_internal(req);

    PGconn *db = auth_db();
    if (!db) return 0;

    session_t session = {0};
    if (rand_bytes(session.csrf_secret, SESSION_CSRF_LEN) != 0) return 0;

    uint64_t now = (uint64_t)time(NULL);
    session.uid = uid;
    session.created_at = now;
    session.last_seen = now;
    session.expires_at = now + SESSION_TTL;
    session.next = NULL;

    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(session.sid, SESSION_ID_LEN) != 0) return 0;

        if (db_session_create(db,
                              session.sid,
                              SESSION_ID_LEN,
                              session.csrf_secret,
                              SESSION_CSRF_LEN,
                              (int64_t)uid,
                              (int64_t)now,
                              (int64_t)session.expires_at)) {
            req->session = session;
            return 1;
        }
    }

    return 0;
}

int create_anonymous_session(http_request_t *req) {
    return create_session(req, 0);
}

int set_session_cookie(http_response_t *res, const session_t *session, long max_age) {
    if (!res || !session) return 0;

    cookie_settings_t opts = {0};
    opts.max_age = max_age;
    opts.samesite = COOKIE_SAMESITE_LAX;
    opts.flags = (COOKIE_FLAG_HTTPONLY | COOKIE_FLAG_SECURE);
    opts.path = "/";

    char sid_hex[SESSION_ID_LEN * 2 + 1];
    if (hex_encode(session->sid, SESSION_ID_LEN, sid_hex, sizeof(sid_hex)) != 0)
        return 0;

    char *cookie_value = build_set_cookie_value(SESSION_COOKIE_NAME, sid_hex, &opts);
    if (!cookie_value) return 0;

    int ok = http_response_add_header(res, "Set-Cookie", cookie_value) == 0;
    free(cookie_value);
    return ok;
}

int session_is_authenticated(const session_t *session) {
    if (!session) return 0;
    if (session->created_at == 0) return 0;
    return session->uid > 0;
}

int destroy_session(unsigned char *sid) {
    if (!sid) return 0;

    pthread_mutex_lock(&anon_session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = anon_session_find_locked(sid, &bucket, &prev);
    if (cur) {
        anon_unlink_session_locked(bucket, prev, cur);
        pthread_mutex_unlock(&anon_session_store.s_lock);
        free(cur);
        return 1;
    }
    pthread_mutex_unlock(&anon_session_store.s_lock);

    PGconn *db = auth_db();
    if (!db) return 0;

    return db_session_delete(db, sid, SESSION_ID_LEN) ? 1 : 0;
}

int get_session(http_request_t *req) {
    if (!req || !req->jar) return 0;

    const char *sid_hex = cookie_jar_get(req->jar, SESSION_COOKIE_NAME);
    if (!sid_hex || !*sid_hex) return 0;

    unsigned char sid[SESSION_ID_LEN];
    if (hex_decode(sid_hex, sid, SESSION_ID_LEN) != 0) return 0;

    uint64_t now = (uint64_t)time(NULL);

    pthread_mutex_lock(&anon_session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = anon_session_find_locked(sid, &bucket, &prev);
    if (cur) {
        if (session_expired(cur, now)) {
            anon_unlink_session_locked(bucket, prev, cur);
            pthread_mutex_unlock(&anon_session_store.s_lock);
            free(cur);
            return 0;
        }

        cur->last_seen = now;
        req->session = *cur;
        req->session.next = NULL;
        pthread_mutex_unlock(&anon_session_store.s_lock);
        return 1;
    }
    pthread_mutex_unlock(&anon_session_store.s_lock);

    PGconn *db = auth_db();
    if (!db) return 0;

    bool found = false;
    bool ok = false;
    int64_t out_uid = 0;
    uint8_t out_csrf_secret[SESSION_CSRF_LEN];
    size_t out_csrf_secret_len = 0;
    int64_t out_expires_at = 0;

    if (!db_session_get_valid(db,
                              sid,
                              SESSION_ID_LEN,
                              (int64_t)now,
                              &found,
                              &ok,
                              &out_uid,
                              out_csrf_secret,
                              sizeof(out_csrf_secret),
                              &out_csrf_secret_len,
                              &out_expires_at)) {
        return 0;
    }

    if (!found) return 0;

    if (!ok || out_uid <= 0 || out_csrf_secret_len != SESSION_CSRF_LEN) {
        (void)db_session_delete(db, sid, SESSION_ID_LEN);
        return 0;
    }

    if (!db_session_touch(db, sid, SESSION_ID_LEN, (int64_t)now)) {
        return 0;
    }

    memset(&req->session, 0, sizeof(req->session));
    memcpy(req->session.sid, sid, SESSION_ID_LEN);
    memcpy(req->session.csrf_secret, out_csrf_secret, SESSION_CSRF_LEN);
    req->session.uid = (uint64_t)out_uid;
    req->session.created_at = now;
    req->session.last_seen = now;
    req->session.expires_at = (uint64_t)out_expires_at;
    req->session.next = NULL;
    return 1;
}

int rotate_session(http_request_t *req) {
    if (!req) return 0;

    unsigned char sid[SESSION_ID_LEN];
    int has_sid = 0;

    if (memcmp(req->session.sid, (unsigned char[SESSION_ID_LEN]){0}, SESSION_ID_LEN) != 0) {
        memcpy(sid, req->session.sid, SESSION_ID_LEN);
        has_sid = 1;
    } else if (req->jar) {
        const char *sid_hex = cookie_jar_get(req->jar, SESSION_COOKIE_NAME);
        if (sid_hex && hex_decode(sid_hex, sid, SESSION_ID_LEN) == 0) {
            has_sid = 1;
        }
    }

    if (!has_sid) return 0;

    uint64_t now = (uint64_t)time(NULL);

    pthread_mutex_lock(&anon_session_store.s_lock);
    size_t old_bucket = 0;
    session_t *prev = NULL;
    session_t *cur = anon_session_find_locked(sid, &old_bucket, &prev);
    if (cur) {
        if (session_expired(cur, now)) {
            anon_unlink_session_locked(old_bucket, prev, cur);
            pthread_mutex_unlock(&anon_session_store.s_lock);
            free(cur);
            return 0;
        }

        unsigned char new_sid[SESSION_ID_LEN];
        size_t new_bucket = 0;
        int found = 0;

        for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
            if (rand_bytes(new_sid, SESSION_ID_LEN) != 0) break;
            new_bucket = sid_hash(new_sid);
            if (!anon_bucket_has_sid_locked(new_bucket, new_sid)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            pthread_mutex_unlock(&anon_session_store.s_lock);
            return 0;
        }

        anon_unlink_session_locked(old_bucket, prev, cur);
        memcpy(cur->sid, new_sid, SESSION_ID_LEN);
        cur->next = anon_session_store.buckets[new_bucket];
        anon_session_store.buckets[new_bucket] = cur;
        anon_session_store.count++;

        cur->last_seen = now;
        req->session = *cur;
        req->session.next = NULL;

        pthread_mutex_unlock(&anon_session_store.s_lock);
        return 1;
    }
    pthread_mutex_unlock(&anon_session_store.s_lock);

    PGconn *db = auth_db();
    if (!db) return 0;

    bool found = false;
    bool ok = false;
    int64_t out_uid = 0;
    uint8_t out_csrf_secret[SESSION_CSRF_LEN];
    size_t out_csrf_secret_len = 0;
    int64_t out_expires_at = 0;

    if (!db_session_get_valid(db,
                              sid,
                              SESSION_ID_LEN,
                              (int64_t)now,
                              &found,
                              &ok,
                              &out_uid,
                              out_csrf_secret,
                              sizeof(out_csrf_secret),
                              &out_csrf_secret_len,
                              &out_expires_at)) {
        return 0;
    }

    if (!found) return 0;

    if (!ok || out_uid <= 0 || out_csrf_secret_len != SESSION_CSRF_LEN) {
        (void)db_session_delete(db, sid, SESSION_ID_LEN);
        return 0;
    }

    unsigned char new_sid[SESSION_ID_LEN];
    int inserted = 0;
    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(new_sid, SESSION_ID_LEN) != 0) break;

        if (db_session_create(db,
                              new_sid,
                              SESSION_ID_LEN,
                              out_csrf_secret,
                              SESSION_CSRF_LEN,
                              out_uid,
                              (int64_t)now,
                              out_expires_at)) {
            inserted = 1;
            break;
        }
    }

    if (!inserted) return 0;

    if (!db_session_delete(db, sid, SESSION_ID_LEN)) {
        (void)db_session_delete(db, new_sid, SESSION_ID_LEN);
        return 0;
    }

    memset(&req->session, 0, sizeof(req->session));
    memcpy(req->session.sid, new_sid, SESSION_ID_LEN);
    memcpy(req->session.csrf_secret, out_csrf_secret, SESSION_CSRF_LEN);
    req->session.uid = (uint64_t)out_uid;
    req->session.created_at = now;
    req->session.last_seen = now;
    req->session.expires_at = (uint64_t)out_expires_at;
    req->session.next = NULL;

    return 1;
}

int create_user(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;

    const char *username = http_request_form_get(req, "username");
    const char *email = http_request_form_get(req, "email");
    const char *password = http_request_form_get(req, "password");
    const char *confirm = http_request_form_get(req, "confirm-password");

    if (!username || !*username || !email || !*email || !password || !*password) return 0;
    if (confirm && *confirm && strcmp(password, confirm) != 0) return 0;

    PGconn *db = auth_db();
    if (!db) return 0;

    char *pw_hash = NULL;
    if (password_hash(password, &pw_hash) != 0) return 0;

    int64_t user_id = 0;
    int ok = db_user_create(db, username, email, pw_hash, &user_id) ? 1 : 0;
    free(pw_hash);
    if (!ok) return 0;

    memset(&res->user, 0, sizeof(res->user));
    res->user.id = (uint64_t)user_id;
    return 1;
}

int get_user(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;

    PGconn *db = auth_db();
    if (!db) return 0;

    const char *id = http_request_form_get(req, "id");
    const char *password = http_request_form_get(req, "password");
    int has_fields = (id && *id) || (password && *password);
    int use_session_lookup = !has_fields;

    if (!use_session_lookup) {
        if (!id || !*id || !password || !*password) return 0;

        bool found = false;
        int64_t user_id = 0;
        char pw_hash[256];
        if (!db_user_find_login(db, id, &found, &user_id, pw_hash, sizeof(pw_hash))) return 0;
        if (!found) return 0;
        if (password_verify(password, pw_hash) != 1) return 0;

        memset(&res->user, 0, sizeof(res->user));
        res->user.id = (uint64_t)user_id;
        return 1;
    }

    if (req->session.created_at == 0 || req->session.uid == 0) return 0;
    if (!db_user_exists(db, req->session.uid)) return 0;

    memset(&res->user, 0, sizeof(res->user));
    res->user.id = req->session.uid;
    return 1;
}
