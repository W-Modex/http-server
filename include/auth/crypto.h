#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int rand_bytes(void* buf, size_t len);

int password_hash(const char *pw, char **out_hash);
int password_verify(const char *pw, const char *stored_hash);


#endif