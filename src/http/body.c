#include "http/body.h"
#include <ctype.h>

#define MAX_FORM_PAIRS 256
#define MAX_JSON_PAIRS 256

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

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p)) p++;
    return p;
}

static int decode_json_hex4(const char *p, uint32_t *out) {
    int h1 = hex_val(p[0]);
    int h2 = hex_val(p[1]);
    int h3 = hex_val(p[2]);
    int h4 = hex_val(p[3]);
    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) return -1;
    *out = (uint32_t)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
    return 0;
}

static int append_utf8(char *dst, size_t dst_cap, size_t *len, uint32_t cp) {
    if (cp <= 0x7F) {
        if (*len + 1 >= dst_cap) return -1;
        dst[(*len)++] = (char)cp;
        return 0;
    }
    if (cp <= 0x7FF) {
        if (*len + 2 >= dst_cap) return -1;
        dst[(*len)++] = (char)(0xC0 | ((cp >> 6) & 0x1F));
        dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
        return 0;
    }
    if (cp <= 0xFFFF) {
        if (*len + 3 >= dst_cap) return -1;
        dst[(*len)++] = (char)(0xE0 | ((cp >> 12) & 0x0F));
        dst[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
        return 0;
    }
    if (cp <= 0x10FFFF) {
        if (*len + 4 >= dst_cap) return -1;
        dst[(*len)++] = (char)(0xF0 | ((cp >> 18) & 0x07));
        dst[(*len)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        dst[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
        return 0;
    }
    return -1;
}

static int parse_json_string(const char **p, const char *end, char **out) {
    if (!p || !out) return -1;
    const char *s = *p;
    if (s >= end || *s != '"') return -1;
    s++;

    size_t max_len = (size_t)(end - s) + 1;
    char *buf = malloc(max_len);
    if (!buf) return -1;

    size_t len = 0;
    while (s < end) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"') {
            s++;
            buf[len] = '\0';
            *out = buf;
            *p = s;
            return 0;
        }
        if (ch == '\\') {
            if (s + 1 >= end) { free(buf); return -1; }
            s++;
            switch (*s) {
                case '"':  buf[len++] = '"'; break;
                case '\\': buf[len++] = '\\'; break;
                case '/':  buf[len++] = '/'; break;
                case 'b':  buf[len++] = '\b'; break;
                case 'f':  buf[len++] = '\f'; break;
                case 'n':  buf[len++] = '\n'; break;
                case 'r':  buf[len++] = '\r'; break;
                case 't':  buf[len++] = '\t'; break;
                case 'u': {
                    if (s + 4 >= end) { free(buf); return -1; }
                    uint32_t cp = 0;
                    if (decode_json_hex4(s + 1, &cp) != 0) { free(buf); return -1; }
                    s += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (s + 2 >= end || s[1] != '\\' || s[2] != 'u') { free(buf); return -1; }
                        if (s + 6 >= end) { free(buf); return -1; }
                        uint32_t lo = 0;
                        if (decode_json_hex4(s + 3, &lo) != 0) { free(buf); return -1; }
                        if (lo < 0xDC00 || lo > 0xDFFF) { free(buf); return -1; }
                        cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
                        s += 6;
                    }
                    if (append_utf8(buf, max_len, &len, cp) != 0) { free(buf); return -1; }
                    break;
                }
                default:
                    free(buf);
                    return -1;
            }
            s++;
            continue;
        }
        if (ch < 0x20) { free(buf); return -1; }
        buf[len++] = (char)ch;
        s++;
    }

    free(buf);
    return -1;
}

static int skip_json_string(const char **p, const char *end) {
    const char *s = *p;
    if (s >= end || *s != '"') return -1;
    s++;
    while (s < end) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"') {
            *p = s + 1;
            return 0;
        }
        if (ch == '\\') {
            if (s + 1 >= end) return -1;
            s++;
            if (*s == 'u') {
                if (s + 4 >= end) return -1;
                for (int i = 1; i <= 4; ++i) {
                    if (hex_val(s[i]) < 0) return -1;
                }
                s += 4;
            }
        } else if (ch < 0x20) {
            return -1;
        }
        s++;
    }
    return -1;
}

static int extract_json_raw(const char **p, const char *end, char **out) {
    const char *s = *p;
    if (s >= end) return -1;
    if (*s != '{' && *s != '[') return -1;

    size_t max_len = (size_t)(end - s);
    char *stack = malloc(max_len + 1);
    if (!stack) return -1;

    size_t depth = 0;
    stack[depth++] = *s;
    s++;

    while (s < end && depth > 0) {
        if (*s == '"') {
            if (skip_json_string(&s, end) != 0) { free(stack); return -1; }
            continue;
        }
        if (*s == '{' || *s == '[') {
            stack[depth++] = *s;
            s++;
            continue;
        }
        if (*s == '}' || *s == ']') {
            if (depth == 0) { free(stack); return -1; }
            char open = stack[depth - 1];
            if ((*s == '}' && open != '{') || (*s == ']' && open != '[')) {
                free(stack);
                return -1;
            }
            depth--;
            s++;
            continue;
        }
        s++;
    }

    if (depth != 0) { free(stack); return -1; }

    size_t len = (size_t)(s - *p);
    char *buf = malloc(len + 1);
    if (!buf) { free(stack); return -1; }
    memcpy(buf, *p, len);
    buf[len] = '\0';
    *out = buf;
    *p = s;
    free(stack);
    return 0;
}

static int parse_json_number(const char **p, const char *end, char **out) {
    const char *s = *p;
    const char *start = s;
    if (s >= end) return -1;
    if (*s == '-') s++;
    if (s >= end) return -1;
    if (*s == '0') {
        s++;
    } else if (isdigit((unsigned char)*s)) {
        while (s < end && isdigit((unsigned char)*s)) s++;
    } else {
        return -1;
    }
    if (s < end && *s == '.') {
        s++;
        if (s >= end || !isdigit((unsigned char)*s)) return -1;
        while (s < end && isdigit((unsigned char)*s)) s++;
    }
    if (s < end && (*s == 'e' || *s == 'E')) {
        s++;
        if (s < end && (*s == '+' || *s == '-')) s++;
        if (s >= end || !isdigit((unsigned char)*s)) return -1;
        while (s < end && isdigit((unsigned char)*s)) s++;
    }

    size_t len = (size_t)(s - start);
    char *buf = malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, start, len);
    buf[len] = '\0';
    *out = buf;
    *p = s;
    return 0;
}

static int parse_json_value(const char **p, const char *end, char **out) {
    const char *s = skip_ws(*p, end);
    if (s >= end) return -1;

    if (*s == '"') {
        *p = s;
        return parse_json_string(p, end, out);
    }
    if (*s == '{' || *s == '[') {
        *p = s;
        return extract_json_raw(p, end, out);
    }
    if (*s == '-' || isdigit((unsigned char)*s)) {
        *p = s;
        return parse_json_number(p, end, out);
    }
    if ((end - s) >= 4 && strncmp(s, "true", 4) == 0) {
        char *buf = strdup("true");
        if (!buf) return -1;
        *out = buf;
        *p = s + 4;
        return 0;
    }
    if ((end - s) >= 5 && strncmp(s, "false", 5) == 0) {
        char *buf = strdup("false");
        if (!buf) return -1;
        *out = buf;
        *p = s + 5;
        return 0;
    }
    if ((end - s) >= 4 && strncmp(s, "null", 4) == 0) {
        char *buf = strdup("null");
        if (!buf) return -1;
        *out = buf;
        *p = s + 4;
        return 0;
    }
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

int http_request_parse_json(http_request_t *req) {
    if (!req) return -1;
    if (req->json_parsed) return 0;

    if (http_request_detect_body_kind(req) != 0) return -1;
    if (req->body_kind != BODY_JSON) return -1;

    if (!req->body || req->body_len == 0) {
        req->json_parsed = 1;
        return 0;
    }

    char *buf = malloc(req->body_len + 1);
    if (!buf) return -1;
    memcpy(buf, req->body, req->body_len);
    buf[req->body_len] = '\0';

    const char *p = buf;
    const char *end = buf + req->body_len;
    p = skip_ws(p, end);
    if (p >= end || *p != '{') {
        free(buf);
        return -1;
    }
    p++;

    size_t count = 0;
    size_t capacity = 0;
    req->json_count = 0;

    p = skip_ws(p, end);
    if (p < end && *p == '}') {
        req->json_parsed = 1;
        free(buf);
        return 0;
    }

    while (p < end) {
        char *key = NULL;
        char *val = NULL;

        p = skip_ws(p, end);
        if (parse_json_string(&p, end, &key) != 0) {
            free(buf);
            http_request_free_parsed_body(req);
            return -1;
        }

        p = skip_ws(p, end);
        if (p >= end || *p != ':') {
            free(key);
            free(buf);
            http_request_free_parsed_body(req);
            return -1;
        }
        p++;

        if (parse_json_value(&p, end, &val) != 0) {
            free(key);
            free(buf);
            http_request_free_parsed_body(req);
            return -1;
        }

        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(req->json_items[i].key, key) == 0) {
                duplicate = 1;
                break;
            }
        }

        if (duplicate) {
            free(key);
            free(val);
        } else {
            if (count >= MAX_JSON_PAIRS) {
                free(key);
                free(val);
                free(buf);
                http_request_free_parsed_body(req);
                return -1;
            }
            if (count == capacity) {
                size_t new_cap = capacity ? capacity * 2 : 8;
                if (new_cap > MAX_JSON_PAIRS) new_cap = MAX_JSON_PAIRS;
                struct json_kv *items = realloc(req->json_items, new_cap * sizeof(*items));
                if (!items) {
                    free(key);
                    free(val);
                    free(buf);
                    http_request_free_parsed_body(req);
                    return -1;
                }
                req->json_items = items;
                capacity = new_cap;
            }

            req->json_items[count].key = key;
            req->json_items[count].val = val;
            count++;
            req->json_count = count;
        }

        p = skip_ws(p, end);
        if (p < end && *p == ',') {
            p++;
            continue;
        }
        if (p < end && *p == '}') {
            p++;
            p = skip_ws(p, end);
            if (p != end) {
                free(buf);
                http_request_free_parsed_body(req);
                return -1;
            }
            req->json_parsed = 1;
            free(buf);
            return 0;
        }

        free(buf);
        http_request_free_parsed_body(req);
        return -1;
    }

    free(buf);
    http_request_free_parsed_body(req);
    return -1;
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

const char *http_request_json_get(const http_request_t *req, const char *key) {
    if (!req || !key || !req->json_parsed) return NULL;
    for (size_t i = 0; i < req->json_count; ++i) {
        if (strcmp(req->json_items[i].key, key) == 0) {
            return req->json_items[i].val;
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

    for (size_t i = 0; i < req->json_count; ++i) {
        free(req->json_items[i].key);
        free(req->json_items[i].val);
    }
    free(req->json_items);
    req->json_items = NULL;
    req->json_count = 0;
    req->json_parsed = 0;
}
