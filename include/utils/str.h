#ifndef UTIL_H
#define UTIL_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define INITIAL_FD_SIZE   16
#define MAX_PATH_LEN      512
#define MAX_QUERY_LEN     1024
#define MAX_METHOD_LEN    16
#define MAX_HEADER_COUNT  100
#define MAX_RESPONSE_HEADERS 100
#define MAX_REQUEST_SIZE  16384
#define MAX_RESPONSE_SIZE 16384
#define MAX_BUFFER        4096
#define MAX_JOB_QUEUE     1024
#define MAX_SESSION_BUCKET 4096
#define MAX_SESSION_SIZE  1000000
#define MAX_USER_BUCKET 4096
#define MAX_USER_SIZE  100000

static inline void DIE(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "Fatal error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
    exit(EXIT_FAILURE);
}

static inline void str_copy(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) return;
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}


static const char* must_getenv(const char* name) {
    const char* v = getenv(name);
    if (!v || v[0] == '\0') {
        fprintf(stderr, "Missing required env var: %s\n", name);
        exit(1);
    }
    return v;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int percent_decode(const char *src, char **out) {
    if (!src || !out) return -1;
    size_t len = strlen(src);
    char *dst = malloc(len + 1);
    if (!dst) return -1;

    size_t di = 0;
    for (size_t i = 0; i < len; ++i) {
        char ch = src[i];
        if (ch == '+') {
            dst[di++] = ' ';
        } else if (ch == '%') {
            if (i + 2 >= len) {
                free(dst);
                return -1;
            }
            int hi = hex_val(src[i + 1]);
            int lo = hex_val(src[i + 2]);
            if (hi < 0 || lo < 0) {
                free(dst);
                return -1;
            }
            dst[di++] = (char)((hi << 4) | lo);
            i += 2;
        } else {
            dst[di++] = ch;
        }
    }
    dst[di] = '\0';
    *out = dst;
    return 0;
}

static int percent_encode(const char *src, char **out) {
    if (!src || !out) return -1;
    size_t len = strlen(src);
    if (len > (SIZE_MAX - 1) / 3) return -1;

    size_t max_len = len * 3 + 1;
    char *dst = malloc(max_len);
    if (!dst) return -1;

    static const char *hex = "0123456789ABCDEF";
    size_t di = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == ' ') {
            dst[di++] = '+';
        } else if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            dst[di++] = (char)ch;
        } else {
            dst[di++] = '%';
            dst[di++] = hex[(ch >> 4) & 0x0F];
            dst[di++] = hex[ch & 0x0F];
        }
    }
    dst[di] = '\0';
    *out = dst;
    return 0;
}

static inline void trim_inplace(char *s) {
    if (!s) return;
    /* trim leading */
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    /* trim trailing */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static int str_case_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static inline void str_append(char *dst, const char *src, size_t size) {
    if (!dst || !src) return;
    strncat(dst, src, size - strlen(dst) - 1);
}

static inline void clear_buffer(char *buf, size_t size) {
    memset(buf, 0, size);
}

static inline int endswith(char* str, char* t) {
    int m = strlen(str);
    int n = strlen(t);
    if (strcmp(str+m-n, t) == 0) return 1;
    else return 0;
}

static inline int replace_all(const unsigned char *buf, size_t len,
                              const char *needle, const char *replacement,
                              unsigned char **out, size_t *out_len) {
    if (!buf || !needle || !replacement || !out || !out_len) return 0;
    *out = NULL;
    *out_len = 0;

    size_t needle_len = strlen(needle);
    if (needle_len == 0) return 0;
    if (len < needle_len) return 1;

    size_t repl_len = strlen(replacement);
    size_t count = 0;
    for (size_t i = 0; i + needle_len <= len; ) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            count++;
            i += needle_len;
        } else {
            i++;
        }
    }
    if (count == 0) return 1;

    size_t new_len = len;
    if (repl_len >= needle_len) {
        size_t diff = repl_len - needle_len;
        if (diff > 0 && count > (SIZE_MAX - len) / diff) return 0;
        new_len += count * diff;
    } else {
        size_t diff = needle_len - repl_len;
        new_len -= count * diff;
    }

    size_t alloc_len = new_len ? new_len : 1;
    unsigned char *dst = malloc(alloc_len);
    if (!dst) return 0;

    size_t src_i = 0;
    size_t dst_i = 0;
    while (src_i + needle_len <= len) {
        if (memcmp(buf + src_i, needle, needle_len) == 0) {
            if (repl_len > 0) {
                memcpy(dst + dst_i, replacement, repl_len);
                dst_i += repl_len;
            }
            src_i += needle_len;
        } else {
            dst[dst_i++] = buf[src_i++];
        }
    }
    while (src_i < len) {
        dst[dst_i++] = buf[src_i++];
    }

    *out = dst;
    *out_len = dst_i;
    return 1;
}



static inline int file_to_buffer(const char *filename, unsigned char **buf, size_t *len) {
    if (!filename || !buf || !len) return -1;
    *buf = NULL;
    *len = 0;
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        printf("Tried to open: %s\n", filename);
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char *data = malloc((size_t)size);
    if (!data) { fclose(f); return -1; }

    size_t read_size = fread(data, 1, (size_t)size, f);
    fclose(f);

    if (read_size != (size_t)size) {
        free(data);
        return -1;
    }

    *buf = data;
    *len = (size_t)size;
    return 0;
}

#endif
