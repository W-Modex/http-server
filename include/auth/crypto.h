#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int rand_bytes(void* buf, size_t len);

int password_hash(const char *pw, char **out_hash);
int password_verify(const char *pw, const char *stored_hash);
int hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len);
int hex_decode(const char *hex_str, unsigned char *out, size_t out_len);
int hex_nibble(char c);
int random_base64url(size_t byte_len, char **out);

#endif
