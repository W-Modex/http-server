#ifndef CSRF_H
#define CSRF_H

#include "http/request.h"
#include "http/response.h"

#define CSRF_HEADER_NAME "X-CSRF-Token"
#define CSRF_FIELD_NAME "csrf_token"
#define CSRF_TOKEN_BYTES 32
#define CSRF_TOKEN_HEX_LEN (CSRF_TOKEN_BYTES * 2)
#define CSRF_TOKEN_PLACEHOLDER "{{CSRF_TOKEN}}"

int csrf_token_hex(const session_t *session, char *out, size_t out_len);
int csrf_validate_request(http_request_t *req);
int csrf_maybe_inject(http_request_t *req, http_response_t *res);

#endif
