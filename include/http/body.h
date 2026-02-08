#ifndef HTTP_BODY_H
#define HTTP_BODY_H

#include "http/request.h"
#include <stdint.h>

int http_request_detect_body_kind(http_request_t* req);
int http_request_parse_form(http_request_t* req);
int http_request_parse_json(http_request_t* req);
const char* http_request_form_get(const http_request_t* req, const char* key);
const char* http_request_json_get(const http_request_t* req, const char* key);
int http_json_get_string_dup(const char *json, const char *key, char **out);
int http_json_get_bool(const char *json, const char *key, int *out);
int http_json_get_int64(const char *json, const char *key, int64_t *out);
void http_request_free_parsed_body(http_request_t* req);

#endif
