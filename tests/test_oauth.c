#include <openssl/evp.h>
#include "auth/oauth.h"
#include "auth/session.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

static int base64url_encode_str(const char *src, char **out) {
    if (!src || !out) return 0;
    *out = NULL;

    size_t src_len = strlen(src);
    if (src_len > (size_t)INT_MAX) return 0;
    size_t cap = ((src_len + 2) / 3) * 4;
    char *buf = malloc(cap + 1);
    if (!buf) return 0;

    int len = EVP_EncodeBlock((unsigned char *)buf, (const unsigned char *)src, (int)src_len);
    if (len < 0) {
        free(buf);
        return 0;
    }

    for (int i = 0; i < len; ++i) {
        if (buf[i] == '+') buf[i] = '-';
        else if (buf[i] == '/') buf[i] = '_';
    }
    while (len > 0 && buf[len - 1] == '=') len--;
    buf[len] = '\0';
    *out = buf;
    return 1;
}

static int build_jwt(const char *payload_json, char **out_jwt) {
    if (!payload_json || !out_jwt) return 0;
    *out_jwt = NULL;

    char *header = NULL;
    char *payload = NULL;
    if (!base64url_encode_str("{\"alg\":\"none\",\"typ\":\"JWT\"}", &header)) goto cleanup;
    if (!base64url_encode_str(payload_json, &payload)) goto cleanup;

    int needed = snprintf(NULL, 0, "%s.%s.sig", header, payload);
    if (needed <= 0) goto cleanup;

    char *jwt = malloc((size_t)needed + 1);
    if (!jwt) goto cleanup;
    if (snprintf(jwt, (size_t)needed + 1, "%s.%s.sig", header, payload) != needed) {
        free(jwt);
        goto cleanup;
    }

    *out_jwt = jwt;
    free(header);
    free(payload);
    return 1;

cleanup:
    free(header);
    free(payload);
    return 0;
}

static void init_flow(oauth_flow_t *flow, oauth_provider_t *provider, const char *nonce) {
    memset(flow, 0, sizeof(*flow));
    memset(provider, 0, sizeof(*provider));
    provider->issuer = "https://accounts.google.com";
    provider->client_id = "client-123";
    flow->provider = provider;
    if (nonce) {
        snprintf(flow->nonce, sizeof(flow->nonce), "%s", nonce);
    }
}

static int test_extract_identity_valid(void) {
    oauth_flow_t flow;
    oauth_provider_t provider;
    init_flow(&flow, &provider, "nonce-1");

    int64_t exp = (int64_t)time(NULL) + 3600;
    char payload[512];
    int len = snprintf(payload, sizeof(payload),
        "{\"iss\":\"https://accounts.google.com\",\"aud\":\"client-123\","
        "\"nonce\":\"nonce-1\",\"exp\":%lld,\"email_verified\":true,"
        "\"email\":\"a@example.com\",\"name\":\"Alice\"}",
        (long long)exp);
    ASSERT_TRUE(len > 0 && (size_t)len < sizeof(payload));

    char *jwt = NULL;
    ASSERT_TRUE(build_jwt(payload, &jwt) == 1);

    char *email = NULL;
    char *username_seed = NULL;
    ASSERT_TRUE(oauth_extract_google_identity_from_id_token(&flow, jwt, &email, &username_seed) == 1);
    ASSERT_TRUE(strcmp(email, "a@example.com") == 0);
    ASSERT_TRUE(strcmp(username_seed, "Alice") == 0);

    free(jwt);
    free(email);
    free(username_seed);
    return 0;
}

static int test_extract_identity_rejects_nonce_mismatch(void) {
    oauth_flow_t flow;
    oauth_provider_t provider;
    init_flow(&flow, &provider, "nonce-expected");

    int64_t exp = (int64_t)time(NULL) + 3600;
    char payload[512];
    int len = snprintf(payload, sizeof(payload),
        "{\"iss\":\"accounts.google.com\",\"aud\":\"client-123\","
        "\"nonce\":\"nonce-other\",\"exp\":%lld,\"email_verified\":true,"
        "\"email\":\"a@example.com\",\"name\":\"Alice\"}",
        (long long)exp);
    ASSERT_TRUE(len > 0 && (size_t)len < sizeof(payload));

    char *jwt = NULL;
    ASSERT_TRUE(build_jwt(payload, &jwt) == 1);

    char *email = NULL;
    char *username_seed = NULL;
    ASSERT_TRUE(oauth_extract_google_identity_from_id_token(&flow, jwt, &email, &username_seed) == 0);
    ASSERT_TRUE(email == NULL);
    ASSERT_TRUE(username_seed == NULL);

    free(jwt);
    return 0;
}

static int test_extract_identity_rejects_aud_mismatch(void) {
    oauth_flow_t flow;
    oauth_provider_t provider;
    init_flow(&flow, &provider, "nonce-2");

    int64_t exp = (int64_t)time(NULL) + 3600;
    char payload[512];
    int len = snprintf(payload, sizeof(payload),
        "{\"iss\":\"https://accounts.google.com\",\"aud\":\"wrong-client\","
        "\"nonce\":\"nonce-2\",\"exp\":%lld,\"email_verified\":true,"
        "\"email\":\"a@example.com\"}",
        (long long)exp);
    ASSERT_TRUE(len > 0 && (size_t)len < sizeof(payload));

    char *jwt = NULL;
    ASSERT_TRUE(build_jwt(payload, &jwt) == 1);

    char *email = NULL;
    char *username_seed = NULL;
    ASSERT_TRUE(oauth_extract_google_identity_from_id_token(&flow, jwt, &email, &username_seed) == 0);
    ASSERT_TRUE(email == NULL);
    ASSERT_TRUE(username_seed == NULL);

    free(jwt);
    return 0;
}

static int test_extract_identity_rejects_unverified_email(void) {
    oauth_flow_t flow;
    oauth_provider_t provider;
    init_flow(&flow, &provider, "nonce-3");

    int64_t exp = (int64_t)time(NULL) + 3600;
    char payload[512];
    int len = snprintf(payload, sizeof(payload),
        "{\"iss\":\"https://accounts.google.com\",\"aud\":\"client-123\","
        "\"nonce\":\"nonce-3\",\"exp\":%lld,\"email_verified\":false,"
        "\"email\":\"a@example.com\"}",
        (long long)exp);
    ASSERT_TRUE(len > 0 && (size_t)len < sizeof(payload));

    char *jwt = NULL;
    ASSERT_TRUE(build_jwt(payload, &jwt) == 1);

    char *email = NULL;
    char *username_seed = NULL;
    ASSERT_TRUE(oauth_extract_google_identity_from_id_token(&flow, jwt, &email, &username_seed) == 0);
    ASSERT_TRUE(email == NULL);
    ASSERT_TRUE(username_seed == NULL);

    free(jwt);
    return 0;
}

static int test_extract_identity_rejects_expired(void) {
    oauth_flow_t flow;
    oauth_provider_t provider;
    init_flow(&flow, &provider, "nonce-4");

    int64_t exp = (int64_t)time(NULL) - 10;
    char payload[512];
    int len = snprintf(payload, sizeof(payload),
        "{\"iss\":\"https://accounts.google.com\",\"aud\":\"client-123\","
        "\"nonce\":\"nonce-4\",\"exp\":%lld,\"email_verified\":true,"
        "\"email\":\"a@example.com\"}",
        (long long)exp);
    ASSERT_TRUE(len > 0 && (size_t)len < sizeof(payload));

    char *jwt = NULL;
    ASSERT_TRUE(build_jwt(payload, &jwt) == 1);

    char *email = NULL;
    char *username_seed = NULL;
    ASSERT_TRUE(oauth_extract_google_identity_from_id_token(&flow, jwt, &email, &username_seed) == 0);
    ASSERT_TRUE(email == NULL);
    ASSERT_TRUE(username_seed == NULL);

    free(jwt);
    return 0;
}

static void free_entry_chain(u_entry_t *entry) {
    while (entry) {
        u_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
}

static void reset_user_store(void) {
    if (!user_store) return;

    for (int i = 1; i <= user_store->count; ++i) {
        free(user_store->users[i].username);
        free(user_store->users[i].email);
        free(user_store->users[i].password_hash);
        user_store->users[i].username = NULL;
        user_store->users[i].email = NULL;
        user_store->users[i].password_hash = NULL;
        user_store->users[i].id = 0;
    }
    for (size_t i = 0; i < MAX_USER_BUCKET; ++i) {
        free_entry_chain(user_store->by_username[i]);
        free_entry_chain(user_store->by_email[i]);
        user_store->by_username[i] = NULL;
        user_store->by_email[i] = NULL;
    }
    user_store->count = 0;
}

static int test_username_collision_suffixes(void) {
    reset_user_store();

    uint64_t uid1 = oauth_find_or_create_user("alice.one@example.com", "Alice");
    uint64_t uid2 = oauth_find_or_create_user("alice.two@example.com", "Alice");
    uint64_t uid3 = oauth_find_or_create_user("alice.three@example.com", "Alice");
    uint64_t uid4 = oauth_find_or_create_user("bob.smith@example.com", NULL);
    uint64_t uid1_again = oauth_find_or_create_user("alice.one@example.com", "Someone Else");

    ASSERT_TRUE(uid1 > 0);
    ASSERT_TRUE(uid2 > 0);
    ASSERT_TRUE(uid3 > 0);
    ASSERT_TRUE(uid4 > 0);
    ASSERT_TRUE(uid1_again == uid1);

    ASSERT_TRUE(strcmp(user_store->users[uid1].username, "alice") == 0);
    ASSERT_TRUE(strcmp(user_store->users[uid2].username, "alice_2") == 0);
    ASSERT_TRUE(strcmp(user_store->users[uid3].username, "alice_3") == 0);
    ASSERT_TRUE(strcmp(user_store->users[uid4].username, "bob.smith") == 0);

    reset_user_store();
    return 0;
}

int main(void) {
    int failures = 0;
    failures += test_extract_identity_valid();
    failures += test_extract_identity_rejects_nonce_mismatch();
    failures += test_extract_identity_rejects_aud_mismatch();
    failures += test_extract_identity_rejects_unverified_email();
    failures += test_extract_identity_rejects_expired();
    failures += test_username_collision_suffixes();

    if (failures == 0) {
        printf("test_oauth passed!\n");
        return 0;
    }

    printf("test_oauth had %d failure(s)\n", failures);
    return 1;
}
