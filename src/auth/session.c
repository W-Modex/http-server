#include "auth/session.h"
#include "auth/cookie.h"
#include "auth/crypto.h"
#include "http/body.h"
#include "http/request.h"
#include "http/response.h"
#include "utils/str.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static s_list_t session_store = {
    .count = 0,
    .s_lock = PTHREAD_MUTEX_INITIALIZER
};

static u_store_t user_store_state = {
    .count = 0,
    .u_lock = PTHREAD_MUTEX_INITIALIZER
};

u_store_t *user_store = &user_store_state;

static size_t user_key_hash(const char *key) {
    if (!key) return 0;
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)key; *p; ++p) {
        h ^= (uint64_t)(*p);
        h *= 1099511628211ULL;
    }
    return (size_t)(h % MAX_USER_BUCKET);
}

static u_entry_t *user_entry_lookup_locked(u_entry_t **buckets, const char *key) {
    if (!buckets || !key) return NULL;
    size_t bucket = user_key_hash(key);
    u_entry_t *cur = buckets[bucket];
    while (cur) {
        if (strcmp(cur->key, key) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

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
    return (now > session->expires_at) || (now - session->last_seen > SESSION_INACTIVITY_TTL);
}

int create_session( http_request_t* req, uint64_t uid) {
    session_t session = {0};

    if (rand_bytes(session.csrf_secret, SESSION_CSRF_LEN) != 0) return 0;

    uint64_t now = (uint64_t)time(NULL);
    session.uid = uid ? uid : 0;
    session.created_at = now;
    session.last_seen = now;
    session.expires_at = now + SESSION_TTL;
    session.next = NULL;

    for (int attempt = 0; attempt < SESSION_CREATE_MAX_ATTEMPTS; ++attempt) {
        if (rand_bytes(session.sid, SESSION_ID_LEN) != 0) return 0;

        pthread_mutex_lock(&session_store.s_lock);
        if (session_store.count >= MAX_SESSION_SIZE) {
            pthread_mutex_unlock(&session_store.s_lock);
            return 0;
        }
        if (!session_find_locked(session.sid, NULL, NULL)) {
            session_t *node = malloc(sizeof(*node));
            if (!node) {
                pthread_mutex_unlock(&session_store.s_lock);
                return 0;
            }
            *node = session;
            size_t bucket = sid_hash(session.sid);
            node->next = session_store.buckets[bucket];
            session_store.buckets[bucket] = node;
            session_store.count++;
            pthread_mutex_unlock(&session_store.s_lock);
            req->session = session;
            return 1;
        }
        pthread_mutex_unlock(&session_store.s_lock);
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

    pthread_mutex_lock(&session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return 0;
    }

    unlink_session_locked(bucket, prev, cur);
    pthread_mutex_unlock(&session_store.s_lock);
    free(cur);
    return 1;
}

int get_session(http_request_t *req) {
    if (!req || !req->jar) return 0;

    const char *sid_hex = cookie_jar_get(req->jar, SESSION_COOKIE_NAME);
    if (!sid_hex || !*sid_hex) return 0;

    unsigned char sid[SESSION_ID_LEN];
    if (hex_decode(sid_hex, sid, SESSION_ID_LEN) != 0) return 0;

    pthread_mutex_lock(&session_store.s_lock);
    size_t bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return 0;
    }

    uint64_t now = (uint64_t)time(NULL);
    if (session_expired(cur, now)) {
        unlink_session_locked(bucket, prev, cur);
        pthread_mutex_unlock(&session_store.s_lock);
        free(cur);
        return 0;
    }

    cur->last_seen = now;
    req->session = *cur;
    req->session.next = NULL;

    pthread_mutex_unlock(&session_store.s_lock);
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

    pthread_mutex_lock(&session_store.s_lock);
    size_t old_bucket = 0;
    session_t *prev = NULL;
    session_t *cur = session_find_locked(sid, &old_bucket, &prev);
    if (!cur) {
        pthread_mutex_unlock(&session_store.s_lock);
        return 0;
    }

    uint64_t now = (uint64_t)time(NULL);
    if (session_expired(cur, now)) {
        unlink_session_locked(old_bucket, prev, cur);
        pthread_mutex_unlock(&session_store.s_lock);
        free(cur);
        return 0;
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
        return 0;
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

    char *pw_hash = NULL;
    if (password_hash(password, &pw_hash) != 0) return 0;

    pthread_mutex_lock(&user_store->u_lock);
    if (user_store->count >= (MAX_USER_SIZE - 1) ||
        user_entry_lookup_locked(user_store->by_username, username) ||
        user_entry_lookup_locked(user_store->by_email, email)) {
        pthread_mutex_unlock(&user_store->u_lock);
        free(pw_hash);
        return 0;
    }

    char *username_copy = strdup(username);
    char *email_copy = strdup(email);
    u_entry_t *username_entry = malloc(sizeof(*username_entry));
    u_entry_t *email_entry = malloc(sizeof(*email_entry));
    if (!username_copy || !email_copy || !username_entry || !email_entry) {
        free(username_copy);
        free(email_copy);
        free(username_entry);
        free(email_entry);
        pthread_mutex_unlock(&user_store->u_lock);
        free(pw_hash);
        return 0;
    }

    uint64_t id = (uint64_t)user_store->count + 1;
    user_t *user = &user_store->users[id];
    user->id = id;
    user->username = username_copy;
    user->email = email_copy;
    user->password_hash = pw_hash;

    size_t uname_bucket = user_key_hash(user->username);
    username_entry->key = user->username;
    username_entry->id = id;
    username_entry->next = user_store->by_username[uname_bucket];
    user_store->by_username[uname_bucket] = username_entry;

    size_t email_bucket = user_key_hash(user->email);
    email_entry->key = user->email;
    email_entry->id = id;
    email_entry->next = user_store->by_email[email_bucket];
    user_store->by_email[email_bucket] = email_entry;

    user_store->count++;
    pthread_mutex_unlock(&user_store->u_lock);

    res->user = *user;
    return 1;
}

int get_user(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;

    const char *id = http_request_form_get(req, "id");
    const char *password = http_request_form_get(req, "password");
    int has_fields = (id && *id) || (password && *password);
    int use_session_lookup = !has_fields;
    if (!use_session_lookup) {
        if (!id || !*id) return 0;
        if (!password || !*password) return 0;
    }

    user_t *user = NULL;
    pthread_mutex_lock(&user_store->u_lock);
    if (use_session_lookup) {
        if (req->session.created_at != 0 &&
            req->session.uid > 0 &&
            req->session.uid <= (uint64_t)user_store->count) {
            user = &user_store->users[req->session.uid];
        }
    } else {
        u_entry_t *entry = user_entry_lookup_locked(user_store->by_email, id);
        if (!entry) {
            entry = user_entry_lookup_locked(user_store->by_username, id);
        }
        if (entry && entry->id > 0 && entry->id <= (uint64_t)user_store->count) {
            user = &user_store->users[entry->id];
        }
    }
    pthread_mutex_unlock(&user_store->u_lock);

    if (!user || !user->password_hash) return 0;
    if (!use_session_lookup && password_verify(password, user->password_hash) != 1) return 0;

    res->user = *user;
    return 1;
}
