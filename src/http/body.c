#include "http/body.h"
#include <ctype.h>

#define MAX_FORM_PAIRS 256

static int str_case_starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (!*s) return 0;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++;
        prefix++;
    }
    return 1;
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

int http_request_detect_body_kind(http_request_t *req) {
    if (!req) return -1;
    const char *ct = http_request_get_header(req, "Content-Type");
    if (!ct || !*ct) {
        req->body_kind = BODY_NONE;
        return 0;
    }
    
    if (str_case_starts_with(ct, "application/x-www-form-urlencoded")) {
        req->body_kind = BODY_FORM;
    } else if (str_case_starts_with(ct, "application/json")) {
        req->body_kind = BODY_JSON;
    } else {
        req->body_kind = BODY_UNSUPPORTED;
    }
    return 0;
}

int http_request_parse_form(http_request_t *req) {
    if (!req) return -1;
    if (req->form_parsed) return 0;

    if (http_request_detect_body_kind(req) != 0) return -1;
    if (req->body_kind != BODY_FORM) return -1;

    if (!req->body || req->body_len == 0) {
        req->form_parsed = 1;
        return 0;
    }

    char *buf = malloc(req->body_len + 1);
    if (!buf) return -1;
    memcpy(buf, req->body, req->body_len);
    buf[req->body_len] = '\0';

    size_t count = 0;
    size_t capacity = 0;
    req->form_count = 0;

    char *saveptr = NULL;
    char *pair = strtok_r(buf, "&", &saveptr);
    while (pair) {
        if (count >= MAX_FORM_PAIRS) {
            free(buf);
            http_request_free_parsed_body(req);
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
            http_request_free_parsed_body(req);
            return -1;
        }
        if (percent_decode(val_part, &val_dec) != 0) {
            free(key_dec);
            free(buf);
            http_request_free_parsed_body(req);
            return -1;
        }

        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(req->form_items[i].key, key_dec) == 0) {
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
            if (new_cap > MAX_FORM_PAIRS) new_cap = MAX_FORM_PAIRS;
            struct form_kv *items = realloc(req->form_items, new_cap * sizeof(*items));
            if (!items) {
                free(key_dec);
                free(val_dec);
                free(buf);
                http_request_free_parsed_body(req);
                return -1;
            }
            req->form_items = items;
            capacity = new_cap;
        }

        req->form_items[count].key = key_dec;
        req->form_items[count].val = val_dec;
        count++;
        req->form_count = count;

        pair = strtok_r(NULL, "&", &saveptr);
    }

    req->form_parsed = 1;
    free(buf);
    return 0;
}

const char *http_request_form_get(const http_request_t *req, const char *key) {
    if (!req || !key || !req->form_parsed) return NULL;
    for (size_t i = 0; i < req->form_count; ++i) {
        if (strcmp(req->form_items[i].key, key) == 0) {
            return req->form_items[i].val;
        }
    }
    return NULL;
}

void http_request_free_parsed_body(http_request_t *req) {
    if (!req) return;
    for (size_t i = 0; i < req->form_count; ++i) {
        free(req->form_items[i].key);
        free(req->form_items[i].val);
    }
    free(req->form_items);
    req->form_items = NULL;
    req->form_count = 0;
    req->form_parsed = 0;
}
