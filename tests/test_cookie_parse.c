#include "auth/cookie.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        printf("FAIL: %s (line %d)\n", #expr, __LINE__); \
        return 1; \
    }

static int test_cookie_parse_basic(void) {
    const char *header = "session=abc123; theme=light";
    cookie_jar_t *jar = cookie_parse_header(header);
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 2);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "session"), "abc123") == 0);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "theme"), "light") == 0);
    cookie_jar_free(jar);
    return 0;
}

static int test_cookie_parse_whitespace_and_flag(void) {
    const char *header = "  a=1 ;   b=two  ; flag  ";
    cookie_jar_t *jar = cookie_parse_header(header);
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 3);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "a"), "1") == 0);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "b"), "two") == 0);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "flag"), "") == 0);
    cookie_jar_free(jar);
    return 0;
}

static int test_cookie_parse_quoted_value(void) {
    const char *header = "token=\"a\\\"b\\\\c\"; other=ok";
    cookie_jar_t *jar = cookie_parse_header(header);
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 2);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "token"), "a\"b\\c") == 0);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "other"), "ok") == 0);
    cookie_jar_free(jar);
    return 0;
}

static int test_cookie_parse_duplicate(void) {
    const char *header = "dup=one; dup=two; other=3";
    cookie_jar_t *jar = cookie_parse_header(header);
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 2);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "dup"), "one") == 0);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "other"), "3") == 0);
    cookie_jar_free(jar);
    return 0;
}

static int test_cookie_parse_empty(void) {
    cookie_jar_t *jar = cookie_parse_header("");
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 0);
    cookie_jar_free(jar);
    return 0;
}

static int test_cookie_parse_skip_empty_parts(void) {
    const char *header = "; ; =bad; good=ok";
    cookie_jar_t *jar = cookie_parse_header(header);
    ASSERT_TRUE(jar != NULL);
    ASSERT_TRUE(jar->count == 1);
    ASSERT_TRUE(strcmp(cookie_jar_get(jar, "good"), "ok") == 0);
    cookie_jar_free(jar);
    return 0;
}

int main() {
    int failures = 0;
    failures += test_cookie_parse_basic();
    failures += test_cookie_parse_whitespace_and_flag();
    failures += test_cookie_parse_quoted_value();
    failures += test_cookie_parse_duplicate();
    failures += test_cookie_parse_empty();
    failures += test_cookie_parse_skip_empty_parts();

    if (failures == 0) {
        printf("test_cookie_parse passed!\n");
        return 0;
    }

    printf("test_cookie_parse had %d failure(s)\n", failures);
    return 1;
}
