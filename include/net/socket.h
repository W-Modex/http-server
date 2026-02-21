#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define NOT_TLS 0
#define HANDSHAKING 1
#define ESTABLISHED 2

int get_listener_fd(const char* port);
int accept_client(int listener);
int send_message(int client_fd, const char* msg, int size);
int recv_message(int client_fd, char* buffer, int size);
int connect_to(char* ip, char* port);
SSL_CTX* init_ssl_ctx();

#endif
