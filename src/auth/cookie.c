#include "auth/cookie.h"
#include "utils/str.h"
#include <string.h>

#define MAX_COOKIE_PAIRS 256

static void cookie_jar_free_items(cookie_jar_t *jar) {
    if (!jar) return;
    for (size_t i = 0; i < jar->count; ++i) {
        free(jar->items[i].name);
        free(jar->items[i].value);
    }
    free(jar->items);
    jar->items = NULL;
    jar->count = 0;
}

static char *cookie_unquote(const char *value) {
    if (!value) return NULL;
    size_t len = strlen(value);
    if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
        char *out = malloc(len - 1);
        if (!out) return NULL;

        size_t di = 0;
        for (size_t i = 1; i + 1 < len; ++i) {
            char ch = value[i];
            if (ch == '\\' && (i + 1) < len - 1) {
                char next = value[i + 1];
                if (next == '\\' || next == '"') {
                    ch = next;
                    i++;
                }
            }
            out[di++] = ch;
        }
        out[di] = '\0';
        return out;
    }
    return strdup(value);
}

static int cookie_value_needs_quotes(const char *value) {
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p <= 0x20 || *p >= 0x7f || *p == ';' || *p == ',' || *p == '"' || *p == '\\') {
            return 1;
        }
    }
    return 0;
}

static char *cookie_escape_value(const char *value) {
    if (!value) return NULL;
    if (!cookie_value_needs_quotes(value)) return strdup(value);

    size_t len = strlen(value);
    size_t extra = 2;
    for (size_t i = 0; i < len; ++i) {
        if (value[i] == '"' || value[i] == '\\') extra++;
    }

    char *out = malloc(len + extra + 1);
    if (!out) return NULL;

    size_t di = 0;
    out[di++] = '"';
    for (size_t i = 0; i < len; ++i) {
        char ch = value[i];
        if (ch == '"' || ch == '\\') {
            out[di++] = '\\';
        }
        out[di++] = ch;
    }
    out[di++] = '"';
    out[di] = '\0';
    return out;
}

static void append_str(char *out, size_t *offset, const char *src) {
    size_t len = strlen(src);
    memcpy(out + *offset, src, len);
    *offset += len;
}

cookie_jar_t *cookie_parse_header(const char *header_value) {
    cookie_jar_t *jar = calloc(1, sizeof(*jar));
    if (!jar) return NULL;

    if (!header_value || !*header_value) return jar;

    char *buf = strdup(header_value);
    if (!buf) {
        free(jar);
        return NULL;
    }

    size_t count = 0;
    size_t capacity = 0;

    char *saveptr = NULL;
    char *part = strtok_r(buf, ";", &saveptr);
    while (part) {
        trim_inplace(part);
        if (*part == '\0') {
            part = strtok_r(NULL, ";", &saveptr);
            continue;
        }

        char *eq = strchr(part, '=');
        char *name = part;
        char *value = NULL;
        if (eq) {
            *eq = '\0';
            value = eq + 1;
        }

        trim_inplace(name);
        if (eq) {
            trim_inplace(value);
        } else {
            value = name + strlen(name);
        }
        if (*name == '\0') {
            part = strtok_r(NULL, ";", &saveptr);
            continue;
        }

        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(jar->items[i].name, name) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            part = strtok_r(NULL, ";", &saveptr);
            continue;
        }

        if (count >= MAX_COOKIE_PAIRS) {
            free(buf);
            cookie_jar_free_items(jar);
            free(jar);
            return NULL;
        }

        char *name_copy = strdup(name);
        char *value_copy = cookie_unquote(value);
        if (!name_copy || !value_copy) {
            free(name_copy);
            free(value_copy);
            free(buf);
            cookie_jar_free_items(jar);
            free(jar);
            return NULL;
        }

        if (count == capacity) {
            size_t new_cap = capacity ? capacity * 2 : 8;
            if (new_cap > MAX_COOKIE_PAIRS) new_cap = MAX_COOKIE_PAIRS;
            cookie_kv_t *items = realloc(jar->items, new_cap * sizeof(*items));
            if (!items) {
                free(name_copy);
                free(value_copy);
                free(buf);
                cookie_jar_free_items(jar);
                free(jar);
                return NULL;
            }
            jar->items = items;
            capacity = new_cap;
        }

        jar->items[count].name = name_copy;
        jar->items[count].value = value_copy;
        count++;
        jar->count = count;

        part = strtok_r(NULL, ";", &saveptr);
    }

    free(buf);
    return jar;
}

const char *cookie_jar_get(const cookie_jar_t *jar, const char *name) {
    if (!jar || !name) return NULL;
    for (size_t i = 0; i < jar->count; ++i) {
        if (strcmp(jar->items[i].name, name) == 0) {
            return jar->items[i].value;
        }
    }
    return NULL;
}

void cookie_jar_free(cookie_jar_t *jar) {
    if (!jar) return;
    cookie_jar_free_items(jar);
    free(jar);
}

char *cookie_build_set_cookie_value(const char *name, const char *value, const cookie_settings_t *settings) {
    if (!name || !*name || !value) return NULL;

    cookie_settings_t opts = {0};
    opts.max_age = COOKIE_MAX_AGE_UNSET;
    opts.samesite = COOKIE_SAMESITE_DEFAULT;
    if (settings) opts = *settings;

    char *value_copy = cookie_escape_value(value);
    if (!value_copy) return NULL;

    const char *samesite = NULL;
    switch (opts.samesite) {
        case COOKIE_SAMESITE_LAX:
            samesite = "Lax";
            break;
        case COOKIE_SAMESITE_STRICT:
            samesite = "Strict";
            break;
        case COOKIE_SAMESITE_NONE:
            samesite = "None";
            break;
        default:
            break;
    }

    size_t len = strlen(name) + 1 + strlen(value_copy);
    if (opts.domain && *opts.domain) len += strlen("; Domain=") + strlen(opts.domain);
    if (opts.path && *opts.path) len += strlen("; Path=") + strlen(opts.path);
    if (opts.expires && *opts.expires) len += strlen("; Expires=") + strlen(opts.expires);
    if (opts.max_age != COOKIE_MAX_AGE_UNSET) {
        len += strlen("; Max-Age=") + (size_t)snprintf(NULL, 0, "%ld", opts.max_age);
    }
    if (samesite) len += strlen("; SameSite=") + strlen(samesite);
    if (opts.flags & COOKIE_FLAG_SECURE) len += strlen("; Secure");
    if (opts.flags & COOKIE_FLAG_HTTPONLY) len += strlen("; HttpOnly");
    if (opts.flags & COOKIE_FLAG_PARTITIONED) len += strlen("; Partitioned");

    char *out = malloc(len + 1);
    if (!out) {
        free(value_copy);
        return NULL;
    }

    size_t offset = 0;
    append_str(out, &offset, name);
    out[offset++] = '=';
    append_str(out, &offset, value_copy);

    if (opts.domain && *opts.domain) {
        append_str(out, &offset, "; Domain=");
        append_str(out, &offset, opts.domain);
    }
    if (opts.path && *opts.path) {
        append_str(out, &offset, "; Path=");
        append_str(out, &offset, opts.path);
    }
    if (opts.expires && *opts.expires) {
        append_str(out, &offset, "; Expires=");
        append_str(out, &offset, opts.expires);
    }
    if (opts.max_age != COOKIE_MAX_AGE_UNSET) {
        append_str(out, &offset, "; Max-Age=");
        offset += (size_t)snprintf(out + offset, len + 1 - offset, "%ld", opts.max_age);
    }
    if (samesite) {
        append_str(out, &offset, "; SameSite=");
        append_str(out, &offset, samesite);
    }
    if (opts.flags & COOKIE_FLAG_SECURE) append_str(out, &offset, "; Secure");
    if (opts.flags & COOKIE_FLAG_HTTPONLY) append_str(out, &offset, "; HttpOnly");
    if (opts.flags & COOKIE_FLAG_PARTITIONED) append_str(out, &offset, "; Partitioned");

    out[offset] = '\0';
    free(value_copy);
    return out;
}
