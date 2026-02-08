#include "auth/crypto.h"
#include "utils/str.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define HASH_ALG "pbkdf2_sha256"
#define HASH_ITERS 200000
#define SALT_LEN 16
#define DK_LEN 32
#define MAX_SALT_LEN 64
#define MAX_DK_LEN 64

int rand_bytes(void *buf, size_t len) {
    unsigned char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(p + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}


int hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    if (!in || !out) return -1;
    if (out_len < (in_len * 2 + 1)) return -1;
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
    return 0;
}

int hex_decode(const char *hex_str, unsigned char *out, size_t out_len) {
    if (!hex_str || !out) return -1;
    size_t hex_len = strlen(hex_str);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_val(hex_str[i * 2]);
        int lo = hex_val(hex_str[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

int password_hash(const char *pw, char **out_hash) {
    if (!pw || !out_hash) return -1;
    *out_hash = NULL;

    unsigned char salt[SALT_LEN];
    unsigned char dk[DK_LEN];
    if (rand_bytes(salt, sizeof(salt)) != 0) return -1;

    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw),
                          salt, (int)sizeof(salt),
                          HASH_ITERS,
                          EVP_sha256(),
                          (int)sizeof(dk), dk) != 1) {
        OPENSSL_cleanse(dk, sizeof(dk));
        return -1;
    }

    char salt_hex[SALT_LEN * 2 + 1];
    char dk_hex[DK_LEN * 2 + 1];
    if (hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex)) != 0 ||
        hex_encode(dk, sizeof(dk), dk_hex, sizeof(dk_hex)) != 0) {
        OPENSSL_cleanse(dk, sizeof(dk));
        return -1;
    }

    int needed = snprintf(NULL, 0, "%s$%u$%s$%s",
                          HASH_ALG, HASH_ITERS, salt_hex, dk_hex);
    if (needed < 0) {
        OPENSSL_cleanse(dk, sizeof(dk));
        return -1;
    }

    char *hash = (char *)malloc((size_t)needed + 1);
    if (!hash) {
        OPENSSL_cleanse(dk, sizeof(dk));
        return -1;
    }

    snprintf(hash, (size_t)needed + 1, "%s$%u$%s$%s",
             HASH_ALG, HASH_ITERS, salt_hex, dk_hex);
    OPENSSL_cleanse(dk, sizeof(dk));

    *out_hash = hash;
    return 0;
}

int password_verify(const char *pw, const char *stored_hash) {
    if (!pw || !stored_hash) return -1;

    char *dup = strdup(stored_hash);
    if (!dup) return -1;

    char *save = NULL;
    char *alg = strtok_r(dup, "$", &save);
    char *iter_s = strtok_r(NULL, "$", &save);
    char *salt_hex = strtok_r(NULL, "$", &save);
    char *dk_hex = strtok_r(NULL, "$", &save);
    char *extra = strtok_r(NULL, "$", &save);

    if (!alg || !iter_s || !salt_hex || !dk_hex || extra) {
        free(dup);
        return -1;
    }

    if (strcmp(alg, HASH_ALG) != 0) {
        free(dup);
        return -1;
    }

    errno = 0;
    char *end = NULL;
    unsigned long iters = strtoul(iter_s, &end, 10);
    if (errno != 0 || end == iter_s || *end != '\0' || iters == 0 || iters > INT_MAX) {
        free(dup);
        return -1;
    }

    size_t salt_hex_len = strlen(salt_hex);
    size_t dk_hex_len = strlen(dk_hex);
    if (salt_hex_len == 0 || dk_hex_len == 0 ||
        (salt_hex_len % 2) != 0 || (dk_hex_len % 2) != 0) {
        free(dup);
        return -1;
    }

    size_t salt_len = salt_hex_len / 2;
    size_t dk_len = dk_hex_len / 2;
    if (salt_len > MAX_SALT_LEN || dk_len > MAX_DK_LEN) {
        free(dup);
        return -1;
    }

    unsigned char *salt = (unsigned char *)malloc(salt_len);
    unsigned char *dk_expected = (unsigned char *)malloc(dk_len);
    unsigned char *dk_actual = (unsigned char *)malloc(dk_len);
    if (!salt || !dk_expected || !dk_actual) {
        free(salt);
        free(dk_expected);
        free(dk_actual);
        free(dup);
        return -1;
    }

    int rc = -1;
    if (hex_decode(salt_hex, salt, salt_len) != 0 ||
        hex_decode(dk_hex, dk_expected, dk_len) != 0) {
        goto cleanup;
    }

    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw),
                          salt, (int)salt_len,
                          (int)iters,
                          EVP_sha256(),
                          (int)dk_len, dk_actual) != 1) {
        goto cleanup;
    }

    if (CRYPTO_memcmp(dk_expected, dk_actual, dk_len) == 0) {
        rc = 1;
    } else {
        rc = 0;
    }

cleanup:
    OPENSSL_cleanse(dk_actual, dk_len);
    OPENSSL_cleanse(dk_expected, dk_len);
    OPENSSL_cleanse(salt, salt_len);
    free(salt);
    free(dk_expected);
    free(dk_actual);
    free(dup);
    return rc;
}
