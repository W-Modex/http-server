#include "http/body.h"
#include "http/response.h"
#include "auth/crypto.h"

int post_login(http_request_t* req, http_response_t* res) {
    if (!res) return 0;
    if (!req) return response_set_error(res, 400, "Bad Request");

    if (http_request_parse_form(req) != 0) return -1;
    const char* username = http_request_form_get(req, "username");
    const char* password = http_request_form_get(req, "password");
    
    
}