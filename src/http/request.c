#include "auth/cookie.h"
#include "utils/str.h"
#include <string.h>
#include "http/body.h"
#include "http/request.h"

#define MAX_QUERY_PAIRS 256

static void free_query_items(http_request_t *req) {
    if (!req) return;
    for (size_t i = 0; i < req->query_count; ++i) {
        free(req->query_items[i].key);
        free(req->query_items[i].val);
    }
    free(req->query_items);
    req->query_items = NULL;
    req->query_count = 0;
    req->query_parsed = 0;
}

static void free_request_partial(http_request_t *req) {
    if (!req) return;
    for (int i = 0; i < req->header_count; ++i) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
    cookie_jar_free(req->jar);
    http_request_free_parsed_body(req);
    free_query_items(req);
    free(req->body);
    free(req);
}

static void set_http_method(http_request_t* req, const char* method) {
    if (strcmp(method, "GET") == 0) req->method = HTTP_GET;
    else if (strcmp(method, "POST") == 0) req->method = HTTP_POST;
    else if (strcmp(method, "PUT") == 0) req->method = HTTP_PUT;
    else if (strcmp(method, "PATCH") == 0) req->method = HTTP_PATCH;
    else if (strcmp(method, "HEAD") == 0) req->method = HTTP_HEAD;
    else if (strcmp(method, "DELETE") == 0) req->method = HTTP_DELETE;
    else req->method = HTTP_UNKNOWN;
}

void free_http_request(http_request_t *req) {
    if (!req) return;
    for (int i = 0; i < req->header_count; ++i) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
    cookie_jar_free(req->jar);
    http_request_free_parsed_body(req);
    free_query_items(req);
    free(req->body);
    free(req);
}

const char *http_request_get_header(const http_request_t *req, const char *name) {
    if (!req || !name) return NULL;
    for (int i = 0; i < req->header_count; ++i) {
        if (str_case_eq(req->headers[i].name, name)) return req->headers[i].value;
    }
    return NULL;
}

const char *get_request_params(const http_request_t *req, const char *key) {
    if (!req || !key || !req->query_parsed) return NULL;
    for (size_t i = 0; i < req->query_count; ++i) {
        if (strcmp(req->query_items[i].key, key) == 0) {
            return req->query_items[i].val;
        }
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

    char *query = strchr(path, '?');
    char *query_str = NULL;
    if (query) {
        *query = '\0';
        query_str = query + 1;
    }

    /* validate lengths */
    if (strlen(method) >= MAX_METHOD_LEN) return -1;
    if (strlen(path) >= sizeof(req->path)) return -1;
    if (query_str && strlen(query_str) >= sizeof(req->query)) return -1;
    if (strlen(ver)  >= sizeof(req->version)) return -1;

    if (strncmp(ver, "HTTP/", 5) != 0) return -1;
    set_http_method(req, method);
    strncpy(req->path, path, sizeof(req->path)-1);
    req->path[sizeof(req->path)-1] = '\0';
    req->query[0] = '\0';
    if (query_str) {
        strncpy(req->query, query_str, sizeof(req->query)-1);
        req->query[sizeof(req->query)-1] = '\0';
    }
    strncpy(req->version, ver, sizeof(req->version)-1);
    req->version[sizeof(req->version)-1] = '\0';

    return 0;
}

static int find_header_separator(const char *raw, size_t raw_len, size_t *sep_len) {
    if (!raw || !sep_len) return -1;
    for (size_t i = 0; i + 3 < raw_len; ++i) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
            *sep_len = 4;
            return (int)i;
        }
    }
    for (size_t i = 0; i + 1 < raw_len; ++i) {
        if (raw[i] == '\n' && raw[i + 1] == '\n') {
            *sep_len = 2;
            return (int)i;
        }
    }
    return -1;
}

static int str_case_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; ++p) {
        size_t i = 0;
        while (i < nlen && p[i]
            && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static int parse_query_params(http_request_t *req) {
    if (!req) return -1;
    req->query_parsed = 1;
    req->query_count = 0;
    if (req->query[0] == '\0') return 0;

    char *buf = strdup(req->query);
    if (!buf) return -1;

    size_t count = 0;
    size_t capacity = 0;
    char *saveptr = NULL;
    char *pair = strtok_r(buf, "&", &saveptr);
    while (pair) {
        if (count >= MAX_QUERY_PAIRS) {
            free(buf);
            free_query_items(req);
            return -1;
        }

        char *eq = strchr(pair, '=');
        char *key_part = pair;
        char *val_part = "";
        if (eq) {
            *eq = '\0';
            val_part = eq + 1;
        }

        char *key_dec = NULL;
        char *val_dec = NULL;
        if (percent_decode(key_part, &key_dec) != 0) {
            free(buf);
            free_query_items(req);
            return -1;
        }
        if (percent_decode(val_part, &val_dec) != 0) {
            free(key_dec);
            free(buf);
            free_query_items(req);
            return -1;
        }

        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(req->query_items[i].key, key_dec) == 0) {
                duplicate = 1;
                break;
            }
        }

        if (duplicate) {
            free(key_dec);
            free(val_dec);
            pair = strtok_r(NULL, "&", &saveptr);
            continue;
        }

        if (count == capacity) {
            size_t new_cap = capacity ? capacity * 2 : 8;
            if (new_cap > MAX_QUERY_PAIRS) new_cap = MAX_QUERY_PAIRS;
            struct query_kv *items = realloc(req->query_items, new_cap * sizeof(*items));
            if (!items) {
                free(key_dec);
                free(val_dec);
                free(buf);
                free_query_items(req);
                return -1;
            }
            req->query_items = items;
            capacity = new_cap;
        }

        req->query_items[count].key = key_dec;
        req->query_items[count].val = val_dec;
        count++;
        req->query_count = count;

        pair = strtok_r(NULL, "&", &saveptr);
    }

    free(buf);
    return 0;
}

/* Main parser */
http_request_t *parse_http_request(const char *raw, size_t raw_len) {
    if (!raw || raw_len == 0) return NULL;

    size_t sep_len = 0;
    int sep_index = find_header_separator(raw, raw_len, &sep_len);
    size_t header_len = (sep_index >= 0) ? (size_t)sep_index : raw_len;
    size_t body_start = (sep_index >= 0) ? (size_t)sep_index + sep_len : raw_len;

    char *buf = malloc(header_len + 1);
    if (!buf) return NULL;
    memcpy(buf, raw, header_len);
    buf[header_len] = '\0';

    http_request_t *req = calloc(1, sizeof(http_request_t));
    if (!req) { free(buf); return NULL; }

    req->body_kind = BODY_NONE;
    req->form_items = NULL;
    req->form_count = 0;
    req->form_parsed = 0;
    req->json_items = NULL;
    req->json_count = 0;
    req->json_parsed = 0;
    req->query_items = NULL;
    req->query_count = 0;
    req->query_parsed = 0;
    req->query[0] = '\0';

    char *saveptr = NULL;
    char *line = strtok_r(buf, "\r\n", &saveptr);
    if (!line) { free_request_partial(req); free(buf); return NULL; }

    if (parse_start_line(line, req) != 0) {
        free_request_partial(req);
        free(buf);
        return NULL;
    }

    if (parse_query_params(req) != 0) {
        free_request_partial(req);
        free(buf);
        return NULL;
    }

    

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
        char *name  = line;
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

    const char* cookie_hdr = http_request_get_header(req, "Cookie");
    if (cookie_hdr) req->jar = cookie_parse_header(cookie_hdr);

    req->body = NULL;
    req->body_len = 0;

    const char *te_hdr = http_request_get_header(req, "Transfer-Encoding");
    if (te_hdr && str_case_contains(te_hdr, "chunked")) {
        free_request_partial(req);
        free(buf);
        return NULL;
    }

    if (http_request_detect_body_kind(req) != 0) {
        free_request_partial(req);
        free(buf);
        return NULL;
    }

    const char *cl_hdr = http_request_get_header(req, "Content-Length");
    if (cl_hdr) {
        char *endptr = NULL;
        long cl = strtol(cl_hdr, &endptr, 10);
        if (endptr == cl_hdr || *endptr != '\0' || cl < 0) {
            free_request_partial(req);
            free(buf);
            return NULL;
        }

        if ((size_t)cl > 0) {
            if (body_start + (size_t)cl > raw_len) {
                free_request_partial(req);
                free(buf);
                return NULL;
            }

            req->body_len = (size_t)cl;
            req->body = malloc(req->body_len);
            if (!req->body) { free_request_partial(req); free(buf); return NULL; }

            memcpy(req->body, raw + body_start, req->body_len);
        }
    }

    free(buf);
    return req;
}
