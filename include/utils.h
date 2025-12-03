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
#define MAX_METHOD_LEN    16
#define MAX_HEADER_COUNT  100
#define MAX_REQUEST_SIZE  8192
#define MAX_RESPONSE_SIZE 16384
#define MAX_BUFFER        4096

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

static inline char* file_to_buffer(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size + 1);
    if (!buf) { fclose(f); return NULL; }

    fread(buf, 1, size, f);
    buf[size] = '\0';

    fclose(f);

    return buf;
}

#endif
