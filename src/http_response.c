#include "../include/http_response.h"
#include "http_parser.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* build_simple_error(int code, const char *text) {
    http_response_t res = {
        .status_code = code,
        .body = "",
        .body_length = 0,
    };

    strncpy(res.status_text, text, sizeof(res.status_text));
    strcpy(res.content_type, "text/plain");

    return build_response(&res);
}

char* build_response(http_response_t *res) {
    char header[512];

    snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        res->status_code,
        res->status_text,
        res->content_type,
        res->body_length
    );

    size_t total = strlen(header) + res->body_length;
    char *final = malloc(total + 1);

    memcpy(final, header, strlen(header));
    memcpy(final + strlen(header), res->body, res->body_length);

    final[total] = '\0';
    return final;
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
    if (strcmp(path, "/") == 0) return strdup("../static/index.html"); 
    if (strstr(path, "..")) return NULL;
    char s[512];
    if (!strchr(path, '.')) 
        sprintf(s, "../static%s/index.html", path);
    else 
        sprintf(s, "../static%s", path);    
    
    return strdup(s);
}

char* handle_response(job_t *j) {
    http_request_t* req = parse_http_request(j->data);
    if (!req) return NULL;

    if (strcmp(req->method, "GET") == 0) {
        return HTTP_GET(req);
    }
    else if (strcmp(req->method, "HEAD") == 0) {
        return HTTP_HEAD(req);
    }

    return build_simple_error(405, "Method Not Allowed");
}

char* HTTP_GET(http_request_t *req) {
    char* filename = resolve_path(req->path);
    if (!filename)
        return build_simple_error(400, "Bad Request");

    char* mime = mime_type(filename);
    printf("mime is: %s, filename is: %s\n", mime, filename);

    char* buf = file_to_buffer(filename);
    printf("buf: %s\n", buf);
    if (!buf) {
        return build_simple_error(404, "Not Found");
    }

    http_response_t res = {
        .status_code = 200,
        .body = buf,
        .body_length = strlen(buf),
    };

    strcpy(res.status_text, "OK");
    strcpy(res.content_type, mime);

    char *final = build_response(&res);

    free(buf);
    return final;
}



char* HTTP_HEAD(http_request_t *req) {

    char filename[512];
    snprintf(filename, sizeof(filename), "../static%sindex.html", req->path);

    char* buf = file_to_buffer(filename);
    if (!buf) {
        return build_simple_error(404, "Not Found");
    }

    http_response_t res = {
        .status_code = 200,
        .body = NULL,
        .body_length = strlen(buf),
    };

    strcpy(res.status_text, "OK");
    strcpy(res.content_type, "text/html");

    free(buf);
    return build_response(&res);
}
