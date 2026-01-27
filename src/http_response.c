#include "../include/http_response.h"
#include "http_parser.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

static http_payload_t http_payload_empty(void) {
    http_payload_t payload = { .data = NULL, .length = 0 };
    return payload;
}

static int is_https_request(int is_ssl, const http_request_t *req) {
    if (is_ssl) return 1;
    if (!req) return 0;
    const char *xfp = http_request_get_header(req, "X-Forwarded-Proto");
    if (xfp && str_case_eq(xfp, "https")) return 1;
    return 0;
}

static http_payload_t build_https_redirect(const http_request_t *req) {
    if (!req) return http_payload_empty();
    const char *host = http_request_get_header(req, "Host");
    if (!host || !*host) return build_simple_error(400, "Bad Request");

    size_t loc_len = strlen("https://") + strlen(host) + strlen(req->path) + 1;
    char *location = malloc(loc_len);
    if (!location) return http_payload_empty();
    snprintf(location, loc_len, "https://%s%s", host, req->path);

    http_response_t res;
    http_response_init(&res, 308, "Permanent Redirect");
    http_response_set_body(&res, (const unsigned char *)"", 0, "text/plain");
    http_response_add_header(&res, "Location", location);
    http_payload_t payload = build_response(&res);
    http_response_clear(&res);
    free(location);
    return payload;
}

http_payload_t build_simple_error(int code, const char *text) {
    http_response_t res;
    http_response_init(&res, code, text);
    http_response_set_body(&res, (const unsigned char *)"", 0, "text/plain");
    http_payload_t payload = build_response(&res);
    http_response_clear(&res);
    return payload;
}

http_payload_t build_response(http_response_t *res) {
    if (!res) return http_payload_empty();
    const char *content_type = res->content_type[0] ? res->content_type : "application/octet-stream";

    char status_line[128];
    int status_len = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
        res->status_code, res->status_text);
    if (status_len < 0) return http_payload_empty();

    char content_length_line[64];
    int content_length_len = snprintf(content_length_line, sizeof(content_length_line),
        "Content-Length: %zu\r\n", res->body_length);
    if (content_length_len < 0) return http_payload_empty();

    size_t header_len = (size_t)status_len;
    header_len += strlen("Content-Type: ") + strlen(content_type) + 2;
    header_len += (size_t)content_length_len;
    for (int i = 0; i < res->header_count; ++i) {
        header_len += strlen(res->headers[i].name) + 2 + strlen(res->headers[i].value) + 2;
    }
    header_len += strlen("Strict-Transport-Security") + 2
        + strlen("max-age=31536000; includeSubDomains") + 2;
    header_len += 2;

    size_t total = header_len + res->body_length;
    char *final = malloc(total + 1);
    if (!final) return http_payload_empty();

    size_t offset = 0;
    memcpy(final + offset, status_line, (size_t)status_len);
    offset += (size_t)status_len;

    append_header_line(final, &offset, "Content-Type", content_type);
    memcpy(final + offset, content_length_line, (size_t)content_length_len);
    offset += (size_t)content_length_len;
    append_header_line(final, &offset, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    
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

    http_payload_t payload = { .data = final, .length = offset };
    return payload;
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
    printf("request path is: %s\n", path);
    if (strcmp(path, "/") == 0) return strdup("../static/index.html"); 
    if (strstr(path, "..")) return NULL;
    char s[512];
    if (!strchr(path, '.')) 
        sprintf(s, "../static%s/index.html", path);
    else 
        sprintf(s, "../static%s", path);    
    
    return strdup(s);
}

http_payload_t handle_response(http_request_t* req, int is_ssl) {
    if (!req) return http_payload_empty();
    if (!is_https_request(is_ssl, req)) return build_https_redirect(req);

    if (strcmp(req->method, "GET") == 0) 
        return HTTP_GET(req);
    else if (strcmp(req->method, "HEAD") == 0)
        return HTTP_HEAD(req);
    else if (strcmp(req->method, "POST") == 0)
        return HTTP_POST(req);
    return build_simple_error(405, "Method Not Allowed");
}

http_payload_t HTTP_GET(http_request_t *req) {
    char* filename = resolve_path(req->path);
    if (!filename)
        return build_simple_error(400, "Bad Request");

    char* mime = mime_type(filename);
    printf("mime is: %s, filename is: %s\n", mime, filename);

    unsigned char *buf = NULL;
    size_t buf_len = 0;
    if (file_to_buffer(filename, &buf, &buf_len) != 0) {
        free(filename);
        return build_simple_error(404, "Not Found");
    }

    http_response_t res;
    http_response_init(&res, 200, "OK");
    http_response_set_body(&res, buf, buf_len, mime);

    http_payload_t payload = build_response(&res);
    http_response_clear(&res);
    free(buf);
    free(filename);
    return payload;
}

http_payload_t HTTP_HEAD(http_request_t *req) {
    char* filename = resolve_path(req->path);
    if (!filename)
        return build_simple_error(400, "Bad Request");

    char* mime = mime_type(filename);
    printf("mime is: %s, filename is: %s\n", mime, filename);

    struct stat st;
    if (stat(filename, &st) != 0) {
        free(filename);
        return build_simple_error(404, "Not Found");
    }

    http_response_t res;
    http_response_init(&res, 200, "OK");
    http_response_set_body(&res, NULL, (size_t)st.st_size, mime);

    http_payload_t payload = build_response(&res);
    http_response_clear(&res);
    free(filename);
    return payload;
}

http_payload_t HTTP_POST(http_request_t* req) {
    (void)req;
    http_response_t res;
    http_response_init(&res, 200, "OK");
    http_response_set_body(&res, (const unsigned char *)"", 0, "text/plain");
    http_payload_t payload = build_response(&res);
    http_response_clear(&res);
    return payload;
}
