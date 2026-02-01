#ifndef COOKIE_H
#define COOKIE_H

#include <stddef.h>

typedef struct {
    char *name;
    char *value;
} cookie_kv_t;

typedef struct {
    cookie_kv_t *items;
    size_t count;
} cookie_jar_t;

typedef enum {
    COOKIE_SAMESITE_DEFAULT = 0,
    COOKIE_SAMESITE_LAX,
    COOKIE_SAMESITE_STRICT,
    COOKIE_SAMESITE_NONE
} cookie_samesite_t;

typedef enum {
    COOKIE_FLAG_NONE = 0,
    COOKIE_FLAG_SECURE = 1 << 0,
    COOKIE_FLAG_HTTPONLY = 1 << 1,
    COOKIE_FLAG_PARTITIONED = 1 << 2
} cookie_flags_t;

#define COOKIE_MAX_AGE_UNSET (-1)

typedef struct {
    const char *domain;
    const char *path;
    const char *expires;
    long max_age;
    cookie_samesite_t samesite;
    unsigned int flags;
} cookie_settings_t;

cookie_jar_t *cookie_parse_header(const char *header_value);
const char *cookie_jar_get(const cookie_jar_t *jar, const char *name);
void cookie_jar_free(cookie_jar_t *jar);
char *cookie_build_set_cookie_value(const char *name, const char *value, const cookie_settings_t *settings);

#endif
