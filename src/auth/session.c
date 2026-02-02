#include "auth/session.h"
#include "auth/crypto.h"
#include "utils/str.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static s_list_t session_store = {
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

static session_t *session_find_locked(const unsigned char *sid, size_t *bucket_out, session_t **prev_out) {
    if (!sid) return NULL;
    size_t bucket = sid_hash(sid);
    if (bucket_out) *bucket_out = bucket;
    session_t *prev = NULL;
    session_t *cur = session_store.buckets[bucket];
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

static int bucket_has_sid(size_t bucket, const unsigned char *sid) {
    session_t *cur = session_store.buckets[bucket];
    while (cur) {
        if (memcmp(cur->sid, sid, SESSION_ID_LEN) == 0) return 1;
        cur = cur->next;
    }
    return 0;
}

static void unlink_session_locked(size_t bucket, session_t *prev, session_t *cur) {
    if (!cur) return;
    if (prev) prev->next = cur->next;
    else session_store.buckets[bucket] = cur->next;
    cur->next = NULL;
    if (session_store.count > 0) session_store.count--;
}

static int session_expired(const session_t *session, uint64_t now) {
    if (!session) return 1;
    if (session->expires_at == 0) return 0;
    return now > session->expires_at;
}

session_t create_session(uint64_t uid) {
    session_t session = {0};

    if (rand_bytes(session.csrf_secret, SESSION_CSRF_LEN) != 0) return session;

    uint64_t now = (uint64_t)time(NULL);
    session.uid = uid ? uid : 0;
    session.created_at = now;
    session.last_seen = now;
    session.expires_at = now + SESSION_TTL;
    session.next = NULL;

    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(session.sid, SESSION_ID_LEN) != 0) return (session_t){0};

        pthread_mutex_lock(&session_store.s_lock);
        if (session_store.count >= MAX_SESSION_SIZE) {
            pthread_mutex_unlock(&session_store.s_lock);
            return (session_t){0};
        }
        if (!session_find_locked(session.sid, NULL, NULL)) {
            session_t *node = malloc(sizeof(*node));
            if (!node) {
                pthread_mutex_unlock(&session_store.s_lock);
                return (session_t){0};
            }
            *node = session;
            size_t bucket = sid_hash(session.sid);
            node->next = session_store.buckets[bucket];
            session_store.buckets[bucket] = node;
            session_store.count++;
            pthread_mutex_unlock(&session_store.s_lock);
            return session;
        }
        pthread_mutex_unlock(&session_store.s_lock);
    }

    return (session_t){0};
}

int destroy_session(unsigned char *sid) {
    if (!sid) return -1;

    pthread_mutex_lock(&session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return -1;
    }

    unlink_session_locked(bucket, prev, cur);
    pthread_mutex_unlock(&session_store.s_lock);
    free(cur);
    return 0;
}

int get_session(http_request_t *req) {
    if (!req || !req->jar) return -1;

    const char *sid_hex = cookie_jar_get(req->jar, SESSION_COOKIE_NAME);
    if (!sid_hex || !*sid_hex) return -1;

    unsigned char sid[SESSION_ID_LEN];
    if (hex_decode(sid_hex, sid, SESSION_ID_LEN) != 0) return -1;

    pthread_mutex_lock(&session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    if (session_expired(cur, now)) {
        unlink_session_locked(bucket, prev, cur);
        pthread_mutex_unlock(&session_store.s_lock);
        free(cur);
        return -1;
    }

    cur->last_seen = now;
    req->session = *cur;
    req->session.next = NULL;

    pthread_mutex_unlock(&session_store.s_lock);
    return 0;
}

int rotate_session(http_request_t *req) {
    if (!req) return -1;

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

    if (!has_sid) return -1;

    pthread_mutex_lock(&session_store.s_lock);
    size_t old_bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &old_bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    if (session_expired(cur, now)) {
        unlink_session_locked(old_bucket, prev, cur);
        pthread_mutex_unlock(&session_store.s_lock);
        free(cur);
        return -1;
    }

    unsigned char new_sid[SESSION_ID_LEN];
    size_t new_bucket = 0;
    int found = 0;
    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(new_sid, SESSION_ID_LEN) != 0) break;
        new_bucket = sid_hash(new_sid);
        if (!bucket_has_sid(new_bucket, new_sid)) {
            found = 1;
            break;
        }
    }
    if (!found) {
        pthread_mutex_unlock(&session_store.s_lock);
        return -1;
    }

    unlink_session_locked(old_bucket, prev, cur);
    memcpy(cur->sid, new_sid, SESSION_ID_LEN);
    cur->next = session_store.buckets[new_bucket];
    session_store.buckets[new_bucket] = cur;
    session_store.count++;

    cur->last_seen = now;
    req->session = *cur;
    req->session.next = NULL;

    pthread_mutex_unlock(&session_store.s_lock);
    return 0;
}
