#ifndef RESPONDER_H
#define RESPONDER_H

#include "http/request.h"
#include "utils/str.h"
#include <bits/pthreadtypes.h>
#include <stdint.h>

typedef struct {
    char *name;
    char *value;
} http_response_header_t;

typedef struct User {
    uint64_t id;
    char* username;
    char* email;
    char* password_hash;
} user_t;

typedef struct u_entry {
    const char* key;
    uint64_t id;
    struct u_entry* next;
} u_entry_t;

typedef struct u_store {
    u_entry_t* by_username[MAX_USER_BUCKET];
    u_entry_t* by_email[MAX_USER_BUCKET];
    user_t users[MAX_USER_SIZE];
    int count;
    pthread_mutex_t u_lock;
} u_store_t;

typedef struct {
    int status_code;
    char status_text[64];

    char content_type[64];

    http_response_header_t headers[MAX_RESPONSE_HEADERS];
    int header_count;

    int body_owned;
    const unsigned char *body;
    size_t body_length;

    user_t user;
} http_response_t;

typedef struct {
    char *data;
    size_t length;
} http_payload_t;

void http_response_init(http_response_t *res, int status_code, const char *status_text);
int http_response_add_header(http_response_t *res, const char *name, const char *value);
void http_response_set_body(http_response_t *res, const unsigned char *body, size_t body_length, const char *content_type);
void http_response_clear(http_response_t *res);

int response_set_error(http_response_t *res, int code, const char *text);
int response_set_redirect(http_response_t *res, int code, const char *location);
int render_html(http_request_t *req, http_response_t *res);
int handle_response(http_request_t* req, http_payload_t* payload);
int build_response(http_response_t *res, http_payload_t* payload);
int build_simple_error(int code, const char *text, http_payload_t* payload);
int build_https_redirect(const http_request_t *req, http_payload_t *payload);
int is_https_request(int is_ssl, const http_request_t *req);

char* resolve_path(char* path);
char* mime_type(char* filename);

int static_get(http_request_t* req, http_response_t* res);
int static_head(http_request_t* req, http_response_t* res);

#endif
