#ifndef UTIL_H
#define UTIL_H

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

static inline void str_trim(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
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
