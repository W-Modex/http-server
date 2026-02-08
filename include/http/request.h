#ifndef PARSER_H
#define PARSER_H

#include "auth/cookie.h"
#include "utils/str.h"
#include <bits/pthreadtypes.h>
#include <stddef.h>

typedef struct {
    char *name;
    char *value;
} header_t;

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_UNKNOWN
} http_method_t;

typedef enum {
    BODY_NONE,
    BODY_FORM,
    BODY_JSON,
    BODY_UNSUPPORTED
} body_kind_t;

typedef struct session {
    unsigned char sid[32];
    unsigned char csrf_secret[32];
    uint64_t uid;
    uint64_t created_at;
    uint64_t last_seen;
    uint64_t expires_at;

    struct session* next;
} session_t;

typedef struct s_list {
    session_t* buckets[MAX_SESSION_BUCKET];
    int count;
    pthread_mutex_t s_lock;
} s_list_t;

struct form_kv {
    char *key;
    char *val;
};

struct json_kv {
    char *key;
    char *val;
};

struct query_kv {
    char *key;
    char *val;
};

typedef struct {
    http_method_t method;
    char path[MAX_PATH_LEN];
    char query[MAX_QUERY_LEN];
    char version[MAX_METHOD_LEN];

    header_t headers[MAX_HEADER_COUNT];
    int header_count;

    cookie_jar_t* jar;

    int is_ssl;

    char *body;      
    size_t body_len;
    
    body_kind_t body_kind;
    struct form_kv *form_items;
    size_t form_count;
    int form_parsed;
    struct json_kv *json_items;
    size_t json_count;
    int json_parsed;

    struct query_kv *query_items;
    size_t query_count;
    int query_parsed;

    session_t session;
} http_request_t;

http_request_t* parse_http_request(const char *raw, size_t raw_len);
void free_http_request(http_request_t *req);
const char* http_request_get_header(const http_request_t *req, const char *name);
const char* get_request_params(const http_request_t *req, const char *key);

#endif
