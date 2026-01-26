#include "../include/network.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int get_listener_fd(char* port) {
    struct addrinfo hints, *res, *p;
    int rv;
    int listen_fd = -1;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rv = getaddrinfo(NULL, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        int sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sfd < 0) {
            continue;
        }

        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("setsockopt(SO_REUSEADDR)");
        }

        #ifdef SO_REUSEPORT
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
            /* ignore */
        }
        #endif

        if (p->ai_family == AF_INET6) {
            int off = 0;
            if (setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0) {
                /* ignore */
            }
        }

        if (bind(sfd, p->ai_addr, p->ai_addrlen) == 0) {
            if (listen(sfd, SOMAXCONN) == 0) {
                listen_fd = sfd;
                break;
            } else {
                perror("listen");
                close(sfd);
                continue;
            }
        } else {
            close(sfd);
            continue;
        }
    }

    freeaddrinfo(res);

    if (listen_fd == -1) {
        fprintf(stderr, "Failed to bind/listen on port %s\n", port);
        return -1;
    }

    return listen_fd;
}

int connect_to(char *ip, char *port) {
    struct addrinfo hints, *res, *p;
    int rv;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo(ip, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        int sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sfd < 0) continue;

        if (connect(sfd, p->ai_addr, p->ai_addrlen) == 0) {
            sockfd = sfd;
            break;
        }

        close(sfd);
    }

    freeaddrinfo(res);

    if (sockfd == -1) {
        perror("connect");
        return -1;
    }

    return sockfd;
}

int accept_client(int listener) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);
    int client_fd;

    client_fd = accept(listener, (struct sockaddr*)&client_addr, &client_addr_size);
    if (client_fd < 0) {
        perror("accept");
        return -1;
    }
    return client_fd;
}

int send_message(int client_fd, const char *msg, int msg_size) {
    if (client_fd < 0 || msg == NULL || msg_size <= 0) return -1;

    int total_sent = 0;
    while (total_sent < msg_size) {
        ssize_t n = send(client_fd, msg + total_sent, msg_size - total_sent, 0);
        if (n > 0) {
            total_sent += (int)n;
            continue;
        }
        if (n == 0) {
            return total_sent;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return total_sent;
        }
        perror("send");
        return -1;
    }
    return total_sent;
}

int recv_message(int client_fd, char *buf, int buf_size) {
    if (client_fd < 0 || buf == NULL || buf_size <= 0) return -1;

    ssize_t n;
    while (1) {
        n = recv(client_fd, buf, (size_t)buf_size, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -1; 
            }
            perror("recv");
            return -1;
        }
        break;
    }

    return (int)n;
}

SSL_CTX* init_ssl_ctx() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Require TLS 1.2+
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Secure options
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_RENEGOTIATION |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_CIPHER_SERVER_PREFERENCE
    );

    // TLS 1.2 ciphers
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256"
    );

    // TLS 1.3 ciphers
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
    );

    // Load cert chain
    if (SSL_CTX_use_certificate_chain_file(ctx, "../certs/chain.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "../certs/pkey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Validate key matches cert
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Session cache ID
    static const unsigned char cache_id[] = "my_tls_server_ctx";
    SSL_CTX_set_session_id_context(ctx, cache_id, sizeof(cache_id));
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    // No client cert required 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}
