#include <openssl/evp.h>
#include "auth/crypto.h"
#include "auth/oauth.h"
#include "auth/session.h"
#include "http/body.h"
#include "utils/str.h"
#include <ctype.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

static oauth_provider_t PROVIDERS[] = {
    {
        .name = "Google",
        .authorize_url = "https://accounts.google.com/o/oauth2/v2/auth",
        .token_url = "https://oauth2.googleapis.com/token",
        .jwks_url = "https://www.googleapis.com/oauth2/v1/certs",
        .issuer = "https://accounts.google.com",
        .client_id = NULL,
        .client_secret = NULL,
        .redirect_uri = "https://modex.work/oauth/google/callback",
        .scope = "openid email profile",
    },
};

static const size_t PROVIDERS_COUNT = (sizeof(PROVIDERS) / sizeof(PROVIDERS[0]));

oauth_flow_store_t oauth_flows = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static pthread_once_t oauth_providers_once = PTHREAD_ONCE_INIT;

static void oauth_providers_init_once(void) {
    const char *client_id = must_getenv("OAUTH_CLIENT_ID");
    const char *client_secret = must_getenv("OAUTH_CLIENT_SECRET");

    for (size_t i = 0; i < PROVIDERS_COUNT; ++i) {
        if (!PROVIDERS[i].client_id) PROVIDERS[i].client_id = client_id;
        if (!PROVIDERS[i].client_secret) PROVIDERS[i].client_secret = client_secret;
    }
}

static void oauth_providers_init(void) {
    (void)pthread_once(&oauth_providers_once, oauth_providers_init_once);
}

static int64_t oauth_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

static size_t oauth_state_hash(const char *state) {
    if (!state) return 0;
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)state; *p; ++p) {
        h ^= (uint64_t)(*p);
        h *= 1099511628211ULL;
    }
    return (size_t)(h % FLOW_BUCKETS);
}

static int base64url_encoded_len(size_t in_len, size_t *out_len) {
    if (!out_len) return 0;
    size_t full = in_len / 3;
    size_t rem = in_len % 3;
    if (full > SIZE_MAX / 4) return 0;
    size_t len = full * 4;
    if (rem) {
        if (len > SIZE_MAX - (rem + 1)) return 0;
        len += rem + 1;
    }
    *out_len = len;
    return 1;
}

static int base64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len) {
    if (!in || !out) return 0;
    size_t needed = 0;
    if (!base64url_encoded_len(in_len, &needed)) return 0;
    if (out_len < needed + 1) return 0;

    static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0;
    size_t o = 0;
    while (i + 2 < in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        out[o++] = alphabet[(v >> 6) & 0x3F];
        out[o++] = alphabet[v & 0x3F];
        i += 3;
    }

    if (in_len - i == 1) {
        uint32_t v = ((uint32_t)in[i] << 16);
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
    } else if (in_len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        out[o++] = alphabet[(v >> 6) & 0x3F];
    }

    out[o] = '\0';
    return 1;
}

static int base64url_encode_alloc(const unsigned char *in, size_t in_len, char **out) {
    if (!out) return 0;
    *out = NULL;
    size_t needed = 0;
    if (!base64url_encoded_len(in_len, &needed)) return 0;
    char *buf = (char *)malloc(needed + 1);
    if (!buf) return 0;
    if (!base64url_encode(in, in_len, buf, needed + 1)) {
        free(buf);
        return 0;
    }
    *out = buf;
    return 1;
}

const oauth_provider_t* get_oauth_provider(const char* name) {
    if (!name) return NULL;
    for (size_t i = 0; i < PROVIDERS_COUNT; i++) {
        if (strcmp(PROVIDERS[i].name, name) == 0) {
            oauth_providers_init();
            return &PROVIDERS[i];
        }
    }
    return NULL;
}

int oauth_flow_store_put(oauth_flow_store_t *store, const oauth_flow_t *flow) {
    if (!store || !flow || !flow->state[0]) return 0;
    size_t bucket = oauth_state_hash(flow->state);

    pthread_mutex_lock(&store->lock);
    oauth_flow_t *cur = store->buckets[bucket];
    while (cur) {
        if (strcmp(cur->state, flow->state) == 0) {
            pthread_mutex_unlock(&store->lock);
            return 0;
        }
        cur = cur->next;
    }

    oauth_flow_t *node = malloc(sizeof(*node));
    if (!node) {
        pthread_mutex_unlock(&store->lock);
        return 0;
    }
    *node = *flow;
    node->next = store->buckets[bucket];
    store->buckets[bucket] = node;
    pthread_mutex_unlock(&store->lock);
    return 1;
}

int oauth_flow_store_get(oauth_flow_store_t *store, const char *state, oauth_flow_t *out) {
    if (!store || !state || !out) return 0;
    size_t bucket = oauth_state_hash(state);
    int64_t now = oauth_now_ms();

    pthread_mutex_lock(&store->lock);
    oauth_flow_t *prev = NULL;
    oauth_flow_t *cur = store->buckets[bucket];
    while (cur) {
        oauth_flow_t *next = cur->next;
        if (now > 0 && cur->expires_at_ms > 0 && now > cur->expires_at_ms) {
            if (prev) prev->next = next;
            else store->buckets[bucket] = next;
            cur->next = NULL;
            free(cur);
            cur = next;
            continue;
        }
        if (strcmp(cur->state, state) == 0) {
            *out = *cur;
            out->next = NULL;
            if (prev) prev->next = next;
            else store->buckets[bucket] = next;
            cur->next = NULL;
            pthread_mutex_unlock(&store->lock);
            free(cur);
            return 1;
        }
        prev = cur;
        cur = next;
    }
    pthread_mutex_unlock(&store->lock);
    return 0;
}

int oauth_pkce_challenge(const char *verifier, char **out_challenge) {
    if (!verifier || !out_challenge) return 0;
    *out_challenge = NULL;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, verifier, strlen(verifier)) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) return 0;

    return base64url_encode_alloc(digest, digest_len, out_challenge);
}

int oauth_build_authorize_url(const oauth_provider_t *p, const char *state,
                              const char *nonce, const char *code_challenge, char **out_url) {
    if (!p || !state || !nonce || !code_challenge || !out_url) return 0;
    if (!p->authorize_url || !p->client_id || !p->redirect_uri || !p->scope) return 0;
    *out_url = NULL;

    char *client_id_enc = NULL;
    char *redirect_enc = NULL;
    char *scope_enc = NULL;
    char *state_enc = NULL;
    char *nonce_enc = NULL;
    char *challenge_enc = NULL;

    if (percent_encode(p->client_id, &client_id_enc) != 0) goto cleanup;
    if (percent_encode(p->redirect_uri, &redirect_enc) != 0) goto cleanup;
    if (percent_encode(p->scope, &scope_enc) != 0) goto cleanup;
    if (percent_encode(state, &state_enc) != 0) goto cleanup;
    if (percent_encode(nonce, &nonce_enc) != 0) goto cleanup;
    if (percent_encode(code_challenge, &challenge_enc) != 0) goto cleanup;

    const char *sep = strchr(p->authorize_url, '?') ? "&" : "?";
    const char *fmt =
        "%s%sresponse_type=code&client_id=%s&redirect_uri=%s&scope=%s"
        "&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256";

    int needed = snprintf(NULL, 0, fmt,
        p->authorize_url, sep, client_id_enc, redirect_enc, scope_enc,
        state_enc, nonce_enc, challenge_enc);
    if (needed < 0) goto cleanup;

    char *url = malloc((size_t)needed + 1);
    if (!url) goto cleanup;
    int written = snprintf(url, (size_t)needed + 1, fmt,
        p->authorize_url, sep, client_id_enc, redirect_enc, scope_enc,
        state_enc, nonce_enc, challenge_enc);
    if (written < 0 || written > needed) {
        free(url);
        goto cleanup;
    }

    *out_url = url;
    free(client_id_enc);
    free(redirect_enc);
    free(scope_enc);
    free(state_enc);
    free(nonce_enc);
    free(challenge_enc);
    return 1;

cleanup:
    free(client_id_enc);
    free(redirect_enc);
    free(scope_enc);
    free(state_enc);
    free(nonce_enc);
    free(challenge_enc);
    return 0;
}

static char *capture_command_output(const char *cmd) {
    if (!cmd || !*cmd) return NULL;

    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 2048;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        pclose(fp);
        return NULL;
    }

    for (;;) {
        if (len + 1024 >= cap) {
            size_t new_cap = cap * 2;
            char *grown = realloc(buf, new_cap);
            if (!grown) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = grown;
            cap = new_cap;
        }

        size_t n = fread(buf + len, 1, cap - len - 1, fp);
        len += n;
        if (n == 0) break;
    }

    buf[len] = '\0';
    int rc = pclose(fp);
    if (rc != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

int oauth_exchange_code_for_id_token(const oauth_flow_t *flow, const char *code, char **out_id_token) {
    if (!flow || !flow->provider || !flow->provider->token_url || !flow->provider->client_id ||
        !flow->provider->client_secret || !flow->provider->redirect_uri || !code || !*code ||
        !flow->code_verifier[0] || !out_id_token) {
        return 0;
    }
    *out_id_token = NULL;

    char *code_enc = NULL;
    char *client_id_enc = NULL;
    char *client_secret_enc = NULL;
    char *redirect_enc = NULL;
    char *verifier_enc = NULL;
    char *cmd = NULL;
    char *resp = NULL;
    char *id_token = NULL;
    int ok = 0;

    if (percent_encode(code, &code_enc) != 0) goto cleanup;
    if (percent_encode(flow->provider->client_id, &client_id_enc) != 0) goto cleanup;
    if (percent_encode(flow->provider->client_secret, &client_secret_enc) != 0) goto cleanup;
    if (percent_encode(flow->provider->redirect_uri, &redirect_enc) != 0) goto cleanup;
    if (percent_encode(flow->code_verifier, &verifier_enc) != 0) goto cleanup;

    const char *fmt =
        "curl -sS --fail -X POST '%s' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "--data 'code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code&code_verifier=%s'";
    int needed = snprintf(NULL, 0, fmt, flow->provider->token_url, code_enc, client_id_enc,
                          client_secret_enc, redirect_enc, verifier_enc);
    if (needed <= 0) goto cleanup;

    cmd = malloc((size_t)needed + 1);
    if (!cmd) goto cleanup;

    if (snprintf(cmd, (size_t)needed + 1, fmt, flow->provider->token_url, code_enc, client_id_enc,
                 client_secret_enc, redirect_enc, verifier_enc) != needed) {
        goto cleanup;
    }

    resp = capture_command_output(cmd);
    if (!resp) goto cleanup;

    if (!http_json_get_string_dup(resp, "id_token", &id_token)) goto cleanup;
    if (!id_token || !*id_token) goto cleanup;

    *out_id_token = id_token;
    id_token = NULL;
    ok = 1;

cleanup:
    free(code_enc);
    free(client_id_enc);
    free(client_secret_enc);
    free(redirect_enc);
    free(verifier_enc);
    free(cmd);
    free(resp);
    free(id_token);
    return ok;
}

static int oauth_decode_base64url(const char *base64url, char **out) {
    if (!base64url || !*base64url || !out) return 0;
    *out = NULL;

    size_t in_len = strlen(base64url);
    if ((in_len % 4) == 1) return 0;
    size_t pad = (4 - (in_len % 4)) % 4;
    if (in_len > SIZE_MAX - pad) return 0;
    size_t b64_len = in_len + pad;
    if (b64_len > (size_t)INT_MAX) return 0;

    char *b64 = malloc(b64_len + 1);
    if (!b64) return 0;
    for (size_t i = 0; i < in_len; ++i) {
        char c = base64url[i];
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        b64[i] = c;
    }
    for (size_t i = in_len; i < b64_len; ++i) b64[i] = '=';
    b64[b64_len] = '\0';

    size_t decoded_cap = (b64_len / 4) * 3;
    char *decoded = malloc(decoded_cap + 1);
    if (!decoded) {
        free(b64);
        return 0;
    }

    int out_len = EVP_DecodeBlock((unsigned char *)decoded, (const unsigned char *)b64, (int)b64_len);
    free(b64);
    if (out_len < 0) {
        free(decoded);
        return 0;
    }

    size_t decoded_len = (size_t)out_len;
    if (decoded_len < pad) {
        free(decoded);
        return 0;
    }
    decoded_len -= pad;
    decoded[decoded_len] = '\0';
    *out = decoded;
    return 1;
}

static int oauth_extract_jwt_payload_json(const char *id_token, char **out_payload_json) {
    if (!id_token || !*id_token || !out_payload_json) return 0;
    *out_payload_json = NULL;

    const char *first_dot = strchr(id_token, '.');
    if (!first_dot) return 0;
    const char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot || second_dot == first_dot + 1) return 0;

    size_t payload_len = (size_t)(second_dot - first_dot - 1);
    char *payload_b64 = malloc(payload_len + 1);
    if (!payload_b64) return 0;
    memcpy(payload_b64, first_dot + 1, payload_len);
    payload_b64[payload_len] = '\0';

    char *payload_json = NULL;
    int ok = oauth_decode_base64url(payload_b64, &payload_json);
    free(payload_b64);
    if (!ok || !payload_json || !*payload_json) {
        free(payload_json);
        return 0;
    }

    *out_payload_json = payload_json;
    return 1;
}

static int oauth_google_issuer_matches(const char *expected, const char *actual) {
    if (!expected || !*expected || !actual || !*actual) return 0;
    if (strcmp(expected, actual) == 0) return 1;
    if (strcmp(expected, "https://accounts.google.com") == 0 && strcmp(actual, "accounts.google.com") == 0) return 1;
    if (strcmp(expected, "accounts.google.com") == 0 && strcmp(actual, "https://accounts.google.com") == 0) return 1;
    return 0;
}

int oauth_extract_google_identity_from_id_token(const oauth_flow_t *flow, const char *id_token,
                                                char **out_email, char **out_username_seed) {
    if (!flow || !flow->provider || !flow->provider->issuer || !flow->provider->client_id ||
        !flow->nonce[0] || !id_token || !*id_token || !out_email || !out_username_seed) {
        return 0;
    }

    *out_email = NULL;
    *out_username_seed = NULL;

    char *payload_json = NULL;
    char *iss = NULL;
    char *aud = NULL;
    char *nonce = NULL;
    char *email = NULL;
    char *name = NULL;
    int email_verified = 0;
    int64_t exp = 0;
    int ok = 0;

    if (!oauth_extract_jwt_payload_json(id_token, &payload_json)) goto cleanup;
    if (!http_json_get_string_dup(payload_json, "iss", &iss) ||
        !oauth_google_issuer_matches(flow->provider->issuer, iss)) {
        goto cleanup;
    }
    if (!http_json_get_string_dup(payload_json, "aud", &aud) ||
        strcmp(aud, flow->provider->client_id) != 0) {
        goto cleanup;
    }
    if (!http_json_get_string_dup(payload_json, "nonce", &nonce) ||
        strcmp(nonce, flow->nonce) != 0) {
        goto cleanup;
    }
    if (!http_json_get_int64(payload_json, "exp", &exp)) goto cleanup;

    time_t now = time(NULL);
    if (now == (time_t)-1 || exp <= (int64_t)now) goto cleanup;

    if (!http_json_get_bool(payload_json, "email_verified", &email_verified) || email_verified != 1) {
        goto cleanup;
    }
    if (!http_json_get_string_dup(payload_json, "email", &email) || !email || !*email) goto cleanup;

    (void)http_json_get_string_dup(payload_json, "name", &name);
    if (name && !*name) {
        free(name);
        name = NULL;
    }

    *out_email = email;
    email = NULL;
    *out_username_seed = name;
    name = NULL;
    ok = 1;

cleanup:
    free(payload_json);
    free(iss);
    free(aud);
    free(nonce);
    free(email);
    free(name);
    return ok;
}

static size_t oauth_user_key_hash(const char *key) {
    if (!key) return 0;
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)key; *p; ++p) {
        h ^= (uint64_t)(*p);
        h *= 1099511628211ULL;
    }
    return (size_t)(h % MAX_USER_BUCKET);
}

static u_entry_t *oauth_user_entry_lookup_locked(u_entry_t **buckets, const char *key) {
    if (!buckets || !key) return NULL;
    size_t bucket = oauth_user_key_hash(key);
    u_entry_t *cur = buckets[bucket];
    while (cur) {
        if (strcmp(cur->key, key) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

static void oauth_sanitize_username(const char *src, int stop_at_at, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';

    if (!src || !*src) return;
    size_t n = 0;
    for (const char *p = src; *p && n + 1 < out_len; ++p) {
        if (stop_at_at && *p == '@') break;
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '-' || c == '_' || c == '.') {
            out[n++] = (char)tolower(c);
        } else {
            out[n++] = '_';
        }
    }

    size_t start = 0;
    while (start < n && out[start] == '_') start++;
    size_t end = n;
    while (end > start && out[end - 1] == '_') end--;
    if (start > 0 || end < n) {
        n = end - start;
        memmove(out, out + start, n);
    }
    out[n] = '\0';
}

static void oauth_build_username_candidate(const char *base, uint64_t suffix, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';

    const char *safe_base = (base && *base) ? base : "user";
    if (suffix < 2) {
        str_copy(out, safe_base, out_len);
        return;
    }

    char suffix_buf[32];
    int suffix_len = snprintf(suffix_buf, sizeof(suffix_buf), "_%llu", (unsigned long long)suffix);
    if (suffix_len <= 0 || (size_t)suffix_len >= sizeof(suffix_buf)) return;

    size_t suffix_sz = (size_t)suffix_len;
    if (out_len <= suffix_sz + 1) {
        str_copy(out, "user", out_len);
        return;
    }

    size_t base_max = out_len - suffix_sz - 1;
    size_t base_len = strlen(safe_base);
    if (base_len == 0) {
        safe_base = "user";
        base_len = strlen(safe_base);
    }
    if (base_len > base_max) base_len = base_max;
    memcpy(out, safe_base, base_len);
    memcpy(out + base_len, suffix_buf, suffix_sz + 1);
}

uint64_t oauth_find_or_create_user(const char *email, const char *username_seed) {
    if (!email || !*email || !user_store) return 0;

    pthread_mutex_lock(&user_store->u_lock);

    u_entry_t *existing = oauth_user_entry_lookup_locked(user_store->by_email, email);
    if (existing && existing->id > 0 && existing->id <= (uint64_t)user_store->count) {
        uint64_t uid = existing->id;
        pthread_mutex_unlock(&user_store->u_lock);
        return uid;
    }

    if (user_store->count >= (MAX_USER_SIZE - 1)) {
        pthread_mutex_unlock(&user_store->u_lock);
        return 0;
    }

    char username_base[96];
    oauth_sanitize_username(username_seed, 0, username_base, sizeof(username_base));
    if (!username_base[0]) {
        oauth_sanitize_username(email, 1, username_base, sizeof(username_base));
    }
    if (!username_base[0]) {
        str_copy(username_base, "user", sizeof(username_base));
    }

    char username[96];
    oauth_build_username_candidate(username_base, 1, username, sizeof(username));
    uint64_t suffix = 2;
    while (oauth_user_entry_lookup_locked(user_store->by_username, username)) {
        oauth_build_username_candidate(username_base, suffix, username, sizeof(username));
        if (suffix == UINT64_MAX) {
            pthread_mutex_unlock(&user_store->u_lock);
            return 0;
        }
        suffix++;
    }

    char *pw_seed = NULL;
    char *pw_hash = NULL;
    if (random_base64url(48, &pw_seed) != 0 || !pw_seed ||
        password_hash(pw_seed, &pw_hash) != 0 || !pw_hash) {
        free(pw_seed);
        free(pw_hash);
        pthread_mutex_unlock(&user_store->u_lock);
        return 0;
    }
    free(pw_seed);

    char *username_copy = strdup(username);
    char *email_copy = strdup(email);
    u_entry_t *username_entry = malloc(sizeof(*username_entry));
    u_entry_t *email_entry = malloc(sizeof(*email_entry));
    if (!username_copy || !email_copy || !username_entry || !email_entry) {
        free(username_copy);
        free(email_copy);
        free(username_entry);
        free(email_entry);
        free(pw_hash);
        pthread_mutex_unlock(&user_store->u_lock);
        return 0;
    }

    uint64_t id = (uint64_t)user_store->count + 1;
    user_t *user = &user_store->users[id];
    user->id = id;
    user->username = username_copy;
    user->email = email_copy;
    user->password_hash = pw_hash;

    size_t uname_bucket = oauth_user_key_hash(user->username);
    username_entry->key = user->username;
    username_entry->id = id;
    username_entry->next = user_store->by_username[uname_bucket];
    user_store->by_username[uname_bucket] = username_entry;

    size_t email_bucket = oauth_user_key_hash(user->email);
    email_entry->key = user->email;
    email_entry->id = id;
    email_entry->next = user_store->by_email[email_bucket];
    user_store->by_email[email_bucket] = email_entry;

    user_store->count++;
    pthread_mutex_unlock(&user_store->u_lock);
    return id;
}
