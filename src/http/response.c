#include "http/response.h"
#include "router/router.h"
#include "auth/csrf.h"
#include "auth/session.h"
#include "utils/str.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *RENDER_NEEDLES[] = {
    CSRF_TOKEN_PLACEHOLDER,
    "{{IS_AUTH}}",
    "{{USERNAME}}",
};

static const size_t RENDER_NEEDLES_COUNT = sizeof(RENDER_NEEDLES) / sizeof(RENDER_NEEDLES[0]);

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

static const char *render_value_for(const char *needle, http_request_t *req,
                                    char *scratch, size_t scratch_len) {
    if (!needle || !req) return "";
    if (strcmp(needle, CSRF_TOKEN_PLACEHOLDER) == 0) {
        if (req->session.created_at != 0 &&
            csrf_token_hex(&req->session, scratch, scratch_len)) {
            return scratch;
        }
        return "";
    }
    if (strcmp(needle, "{{IS_AUTH}}") == 0) {
        return session_is_authenticated(&req->session) ? "Logout" : "Login";
    }
    if (strcmp(needle, "{{USERNAME}}") == 0) {
        uint64_t uid = req->session.uid;
        if (req->session.created_at == 0 || uid == 0 || !user_store) return "";
        if (uid > (uint64_t)user_store->count) return "";

        const user_t *user = &user_store->users[uid];
        if (!user->username || !*user->username) return "";
        return user->username;
    }
    return "";
}

static int replace_in_response(http_response_t *res, const char *needle, const char *replacement) {
    if (!res || !needle || !replacement) return 0;
    if (!res->body || res->body_length == 0) return 1;

    unsigned char *out = NULL;
    size_t out_len = 0;
    if (!replace_all(res->body, res->body_length, needle, replacement, &out, &out_len)) {
        return 0;
    }
    if (!out) return 1;

    if (res->body_owned && res->body) free((void *)res->body);
    res->body = out;
    res->body_length = out_len;
    res->body_owned = 1;
    return 1;
}

static void append_header_line(char *out, size_t *offset, const char *name, const char *value) {
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    memcpy(out + *offset, name, name_len);
    *offset += name_len;
    out[(*offset)++] = ':';
    out[(*offset)++] = ' ';
    memcpy(out + *offset, value, value_len);
    *offset += value_len;
    out[(*offset)++] = '\r';
    out[(*offset)++] = '\n';
}

void http_response_init(http_response_t *res, int status_code, const char *status_text) {
    if (!res) return;
    memset(res, 0, sizeof(*res));
    res->status_code = status_code;
    if (status_text) {
        str_copy(res->status_text, status_text, sizeof(res->status_text));
    }
}

int http_response_add_header(http_response_t *res, const char *name, const char *value) {
    if (!res || !name || !value) return -1;
    if (res->header_count >= MAX_RESPONSE_HEADERS) return -1;
    res->headers[res->header_count].name = strdup(name);
    res->headers[res->header_count].value = strdup(value);
    if (!res->headers[res->header_count].name || !res->headers[res->header_count].value) {
        free(res->headers[res->header_count].name);
        free(res->headers[res->header_count].value);
        return -1;
    }
    res->header_count++;
    return 0;
}

void http_response_set_body(http_response_t *res, const unsigned char *body, size_t body_length, const char *content_type) {
    if (!res) return;
    res->body = body;
    res->body_length = body_length;
    if (content_type) {
        str_copy(res->content_type, content_type, sizeof(res->content_type));
    }
}

void http_response_clear(http_response_t *res) {
    if (!res) return;
    for (int i = 0; i < res->header_count; ++i) {
        free(res->headers[i].name);
        free(res->headers[i].value);
        res->headers[i].name = NULL;
        res->headers[i].value = NULL;
    }
    res->header_count = 0;
}

static void http_payload_clear(http_payload_t *payload) {
    if (!payload) return;
    payload->data = NULL;
    payload->length = 0;
}

int response_set_error(http_response_t *res, int code, const char *text) {
    if (!res) return 0;
    http_response_init(res, code, text);
    http_response_set_body(res, (const unsigned char *)"", 0, "text/plain");
    return 1;
}

static const char *redirect_status_text(int code) {
    switch (code) {
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        default: return "Redirect";
    }
}

int response_set_redirect(http_response_t *res, int code, const char *location) {
    if (!res || !location || !*location) return 0;
    if (code == 0) code = 302;
    http_response_init(res, code, redirect_status_text(code));
    http_response_set_body(res, (const unsigned char *)"", 0, "text/plain");
    if (http_response_add_header(res, "Location", location) != 0) return 0;
    return 1;
}

int render_html(http_request_t *req, http_response_t *res) {
    if (!req || !res) return 0;
    if (!res->body || res->body_length == 0) return 1;
    if (!res->content_type[0] ||
        !str_case_starts_with(res->content_type, "text/html")) {
        return 1;
    }

    char scratch[CSRF_TOKEN_HEX_LEN + 1];
    for (size_t i = 0; i < RENDER_NEEDLES_COUNT; ++i) {
        const char *needle = RENDER_NEEDLES[i];
        const char *replacement = render_value_for(needle, req, scratch, sizeof(scratch));
        if (!replace_in_response(res, needle, replacement)) return 0;
    }
    return 1;
}

int is_https_request(int is_ssl, const http_request_t *req) {
    if (is_ssl) return 1;
    if (!req) return 0;
    const char *xfp = http_request_get_header(req, "X-Forwarded-Proto");
    if (xfp && str_case_eq(xfp, "https")) return 1;
    return 0;
}

int build_https_redirect(const http_request_t *req, http_payload_t *payload) {
    if (!req || !payload) return 0;
    const char *host = http_request_get_header(req, "Host");
    if (!host || !*host) return build_simple_error(400, "Bad Request", payload);

    size_t loc_len = strlen("https://") + strlen(host) + strlen(req->path) + 1;
    char *location = malloc(loc_len);
    if (!location) return 0;
    snprintf(location, loc_len, "https://%s%s", host, req->path);

    http_response_t res;
    if (!response_set_redirect(&res, 308, location)) {
        free(location);
        return 0;
    }
    int ok = build_response(&res, payload);
    http_response_clear(&res);
    free(location);
    return ok;
}

int build_simple_error(int code, const char *text, http_payload_t *payload) {
    if (!payload) return 0;
    http_response_t res;
    http_response_init(&res, code, text);
    http_response_set_body(&res, (const unsigned char *)"", 0, "text/plain");
    int ok = build_response(&res, payload);
    http_response_clear(&res);
    return ok;
}

int build_response(http_response_t *res, http_payload_t *payload) {
    if (!res || !payload) return 0;
    http_payload_clear(payload);
    char *content_type = res->content_type[0] ? res->content_type : "application/octet-stream";

    char status_line[128];
    int status_len = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
        res->status_code, res->status_text);
    if (status_len < 0) return 0;

    char content_length_line[64];
    int content_length_len = snprintf(content_length_line, sizeof(content_length_line),
        "Content-Length: %zu\r\n", res->body_length);
    if (content_length_len < 0) return 0;

    res->headers[res->header_count].name = strdup("Content-Type");
    res->headers[res->header_count++].value = strdup(content_type);
    res->headers[res->header_count].name = strdup("Strict-Transport-Security");
    res->headers[res->header_count++].value = strdup("max-age=31536000; includeSubDomains");

    size_t header_len = (size_t)status_len;
    header_len += (size_t)content_length_len;
    for (int i = 0; i < res->header_count; ++i) {
        header_len += strlen(res->headers[i].name) + 2 + strlen(res->headers[i].value) + 2;
    }
    header_len += 2;
    
    size_t total = header_len + res->body_length;
    char *final = malloc(total + 1);
    if (!final) return 0;

    size_t offset = 0;
    memcpy(final + offset, status_line, (size_t)status_len);
    offset += (size_t)status_len;

    memcpy(final + offset, content_length_line, (size_t)content_length_len);
    offset += (size_t)content_length_len;
    
    for (int i = 0; i < res->header_count; ++i) {
        append_header_line(final, &offset, res->headers[i].name, res->headers[i].value);
    }
    final[offset++] = '\r';
    final[offset++] = '\n';

    if (res->body_length > 0 && res->body) {
        memcpy(final + offset, res->body, res->body_length);
        offset += res->body_length;
    }
    final[offset] = '\0';

    payload->data = final;
    payload->length = offset;
    return 1;
}

char* mime_type(char *filename) {
    if (!filename) return "application/octet-stream";

    if (endswith(filename, ".html")) return "text/html";
    if (endswith(filename, ".css"))  return "text/css";
    if (endswith(filename, ".js"))   return "application/javascript";
    if (endswith(filename, ".png"))  return "image/png";
    if (endswith(filename, ".jpg"))  return "image/jpeg";
    return "application/octet-stream";
}

char* resolve_path(char* path) {
    if (!path) return NULL;

    while (*path == '/') path++;

    char clean_path[MAX_PATH_LEN];
    if (*path == '\0') {
        str_copy(clean_path, "index.html", sizeof(clean_path));
    } else {
        size_t path_len = strlen(path);
        if (path_len >= sizeof(clean_path)) return NULL;
        str_copy(clean_path, path, sizeof(clean_path));
    }

    if (strstr(clean_path, "..")) return NULL;

    size_t clean_len = strlen(clean_path);
    if (clean_len > 0) {
        if (clean_path[clean_len - 1] == '/') {
            const char *suffix = "index.html";
            if (clean_len + strlen(suffix) >= sizeof(clean_path)) return NULL;
            str_append(clean_path, suffix, sizeof(clean_path));
        } else if (!strchr(clean_path, '.')) {
            const char *suffix = "/index.html";
            if (clean_len + strlen(suffix) >= sizeof(clean_path)) return NULL;
            str_append(clean_path, suffix, sizeof(clean_path));
        }
    }

    size_t full_len = strlen(STATIC_DIR) + 1 + strlen(clean_path) + 1;
    char *full_path = malloc(full_len);
    if (!full_path) return NULL;

    int written = snprintf(full_path, full_len, "%s/%s", STATIC_DIR, clean_path);
    if (written < 0 || (size_t)written >= full_len) {
        free(full_path);
        return NULL;
    }

    return full_path;
}

int handle_response(http_request_t* req, http_payload_t* payload) {
    if (!payload) return 0;
    http_payload_clear(payload);
    if (!req) return build_simple_error(400, "Bad Request", payload);
    if (!is_https_request(req->is_ssl, req)) return build_https_redirect(req, payload);

    http_response_t res;
    int routed = router_dispatch(req, &res);
    if (routed == 0) {
        switch (req->method) {
            case HTTP_GET:
                routed = static_get(req, &res);
                break;
            case HTTP_HEAD:
                routed = static_head(req, &res);
                break;
            default:
                routed = response_set_error(&res, 405, "Method Not Allowed");
        }
    }
    if (routed <= 0) return build_simple_error(500, "Internal Server Error", payload);

    int ok = build_response(&res, payload);

    if (res.body_owned && res.body) {
        free((void *)res.body);
    }

    http_response_clear(&res);

    return ok;
}

int static_get(http_request_t *req, http_response_t *res) {
    if (!res) return 0;
    if (!req) return response_set_error(res, 400, "Bad Request");
    char* filename = resolve_path(req->path);
    if (!filename)
        return response_set_error(res, 400, "Bad Request");

    char* mime = mime_type(filename);

    unsigned char *buf = NULL;
    size_t buf_len = 0;
    if (file_to_buffer(filename, &buf, &buf_len) != 0) {
        free(filename);
        return response_set_error(res, 404, "Not Found");
    }
    
    http_response_init(res, 200, "OK");
    http_response_set_body(res, buf, buf_len, mime);
    res->body_owned = 1;
    
    free(filename);
    return 1;
}

int static_head(http_request_t *req, http_response_t *res) {
    if (!res) return 0;
    if (!req) return response_set_error(res, 400, "Bad Request");
    char* filename = resolve_path(req->path);
    if (!filename)
        return response_set_error(res, 400, "Bad Request");

    char* mime = mime_type(filename);

    struct stat st;
    if (stat(filename, &st) != 0) {
        free(filename);
        return response_set_error(res, 404, "Not Found");
    }

    http_response_init(res, 200, "OK");
    http_response_set_body(res, NULL, (size_t)st.st_size, mime);
    free(filename);
    return 1;
}
