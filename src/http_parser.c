#include "../include/utils.h"
#include "http_parser.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void free_request_partial(http_request_t *req) {
    if (!req) return;
    for (int i = 0; i < req->header_count; ++i) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
    free(req->body);
    free(req);
}

void free_http_request(http_request_t *req) {
    if (!req) return;
    for (int i = 0; i < req->header_count; ++i) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
    free(req->body);
    free(req);
}

/* Case-insensitive header lookup */
const char *http_request_get_header(const http_request_t *req, const char *name) {
    if (!req || !name) return NULL;
    for (int i = 0; i < req->header_count; ++i) {
        if (str_case_eq(req->headers[i].name, name)) return req->headers[i].value;
    }
    return NULL;
}

static int parse_start_line(char *line, http_request_t *req) {
    if (!line || !req) return -1;

    char *sp = NULL;
    char *method = strtok_r(line, " ", &sp);
    char *path   = strtok_r(NULL, " ", &sp);
    char *ver    = strtok_r(NULL, " ", &sp);

    if (!method || !path || !ver) return -1;

    /* validate lengths */
    if (strlen(method) >= sizeof(req->method)) return -1;
    if (strlen(path) >= sizeof(req->path)) return -1;
    if (strlen(ver)  >= sizeof(req->version)) return -1;

    /* basic validation of version (should start with "HTTP/") */
    if (strncmp(ver, "HTTP/", 5) != 0) return -1;

    strncpy(req->method, method, sizeof(req->method)-1);
    req->method[sizeof(req->method)-1] = '\0';
    strncpy(req->path, path, sizeof(req->path)-1);
    req->path[sizeof(req->path)-1] = '\0';
    strncpy(req->version, ver, sizeof(req->version)-1);
    req->version[sizeof(req->version)-1] = '\0';

    return 0;
}

/* Main parser */
http_request_t *parse_http_request(const char *raw) {
    if (!raw) return NULL;

    char *buf = strdup(raw);
    if (!buf) return NULL;

    http_request_t *req = calloc(1, sizeof(http_request_t));
    if (!req) { free(buf); return NULL; }

    char *body_start = strstr(buf, "\r\n\r\n");
    size_t header_end_offset = 0;
    if (body_start) {
        header_end_offset = (size_t)(body_start - buf) + 4; 
    } else {
        body_start = strstr(buf, "\n\n");
        if (body_start) header_end_offset = (size_t)(body_start - buf) + 2;
    }

    char *saveptr = NULL;
    char *line = strtok_r(buf, "\r\n", &saveptr); 
    if (!line) { free_request_partial(req); free(buf); return NULL; }

    if (parse_start_line(line, req) != 0) { free_request_partial(req); free(buf); return NULL; }

    req->header_count = 0;
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        if (line[0] == '\0') break;

        char *colon = strchr(line, ':');
        if (!colon) {
            free_request_partial(req);
            free(buf);
            return NULL;
        }

        *colon = '\0';
        char *name = line;
        char *value = colon + 1;
        trim_inplace(name);
        trim_inplace(value);

        if (req->header_count >= MAX_HEADER_COUNT) {
            free_request_partial(req);
            free(buf);
            return NULL;
        }

        req->headers[req->header_count].name  = strdup(name);
        req->headers[req->header_count].value = strdup(value);
        if (!req->headers[req->header_count].name || !req->headers[req->header_count].value) {
            free_request_partial(req);
            free(buf);
            return NULL;
        }
        req->header_count++;
    }

    req->body = NULL;
    req->body_len = 0;
    const char *cl_hdr = http_request_get_header(req, "Content-Length");
    if (cl_hdr) {
        char *endptr = NULL;
        long cl = strtol(cl_hdr, &endptr, 10);
        if (endptr == cl_hdr || cl < 0) { free_request_partial(req); free(buf); return NULL; }

        if (header_end_offset == 0) {
            char *p = strstr(buf, "\r\n\r\n");
            if (p) header_end_offset = (size_t)(p - buf) + 4;
            else {
                p = strstr(buf, "\n\n");
                if (p) header_end_offset = (size_t)(p - buf) + 2;
            }
            if (header_end_offset == 0) { free_request_partial(req); free(buf); return NULL; }
        }

        size_t buf_len = strlen(buf);
        if (header_end_offset + (size_t)cl > buf_len) {
            free_request_partial(req);
            free(buf);
            return NULL;
        }

        req->body_len = (size_t)cl;
        req->body = malloc(req->body_len + 1);
        if (!req->body) { free_request_partial(req); free(buf); return NULL; }
        memcpy(req->body, buf + header_end_offset, req->body_len);
        req->body[req->body_len] = '\0';
    }

    free(buf);
    return req;
}