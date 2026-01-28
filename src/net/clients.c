#include "net/clients.h"
#include <fcntl.h>
#include "net/socket.h"
#include "utils/str.h"
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

void process_connections(cxt_t* cxt, int listener, int ssl_listener) {
    struct pollfd *local_pfds = NULL;
    int local_fdcount = 0;

    pthread_mutex_lock(&cxt->pfds_lock);
    local_fdcount = cxt->fdcount;
    if (local_fdcount > 0) {
        local_pfds = malloc(sizeof(struct pollfd) * local_fdcount);
        if (local_pfds) {
            memcpy(local_pfds, cxt->pfds, sizeof(struct pollfd) * local_fdcount);
        }
    }
    pthread_mutex_unlock(&cxt->pfds_lock);

    if (!local_pfds) return;

    for (int i = 0; i < local_fdcount; ++i) {
        short re = local_pfds[i].revents;
        int fd = local_pfds[i].fd;

        if (re & (POLLIN | POLLOUT)) {
            if (fd == listener) {
                add_connection(cxt, listener, 0);
            } else if (fd == ssl_listener) {
                add_connection(cxt, ssl_listener, 1);
            } else {
                if (re & POLLOUT)
                    handle_client_send(cxt, fd);
                else if (re & POLLIN)
                    handle_client_read(cxt, fd);
            }
        }
    }

    free(local_pfds);
}

void add_connection(cxt_t* cxt, int listener, int is_ssl) {
    int client_fd = accept_client(listener);
    if (client_fd < 0) {
        perror("failed to accept client");
        return;
    }
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    SSL* new_ssl = NULL;

    pthread_mutex_lock(&cxt->pfds_lock);
    //Dymanic resizing
    if (cxt->fdcount == cxt->fdsize) {
        int new_size = cxt->fdsize * 2;
        struct pollfd *new_pfds = realloc(cxt->pfds, new_size * sizeof(struct pollfd));
        if (!new_pfds) { perror("realloc pfds"); close(client_fd); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        cxt->pfds = new_pfds;

        client_t *new_clients = realloc(cxt->clients, new_size * sizeof(client_t));
        if (!new_clients) { perror("realloc clients"); close(client_fd); pthread_mutex_unlock(&cxt->pfds_lock); return; }
        size_t old = cxt->fdsize;
        cxt->clients = new_clients;
        if (new_size > old) {
            memset(&cxt->clients[old], 0, (new_size - old) * sizeof(client_t));
        }
        cxt->fdsize = new_size;
    }

    if (is_ssl) {
        new_ssl = SSL_new(cxt->ssl_ctx);
        if (new_ssl == NULL) {
            ERR_print_errors_fp(stderr);
            pthread_mutex_unlock(&cxt->pfds_lock);
            close(client_fd);
            return;
        }

        SSL_set_fd(new_ssl, client_fd);
        int r = SSL_accept(new_ssl);

        if (r == 1) {
            cxt->clients[cxt->fdcount].is_ssl = ESTABLISHED;
            cxt->pfds[cxt->fdcount].events = POLLIN;
        } else {
            int err = SSL_get_error(new_ssl, r);
            
            if (err == SSL_ERROR_WANT_READ) {
                cxt->pfds[cxt->fdcount].events = POLLIN;
                cxt->clients[cxt->fdcount].is_ssl = HANDSHAKING;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                cxt->pfds[cxt->fdcount].events = POLLOUT;
                cxt->clients[cxt->fdcount].is_ssl = HANDSHAKING;
            } else {
                pthread_mutex_unlock(&cxt->pfds_lock);
                SSL_free(new_ssl);
                close(client_fd);
                return;
            }
        }
    } else {
        cxt->clients[cxt->fdcount].is_ssl = NOT_TLS;
        cxt->pfds[cxt->fdcount].events = POLLIN;
    }

    cxt->clients[cxt->fdcount].fd = client_fd;
    cxt->clients[cxt->fdcount].ssl = new_ssl;
    cxt->clients[cxt->fdcount].write_buf = NULL;
    cxt->clients[cxt->fdcount].write_len = 0;
    cxt->clients[cxt->fdcount].write_send = 0;
    memset(cxt->clients[cxt->fdcount].read_buf, 0, MAX_REQUEST_SIZE);

    cxt->pfds[cxt->fdcount].fd = client_fd;
    cxt->pfds[cxt->fdcount].revents = 0;
    cxt->fdcount++;

    pthread_mutex_unlock(&cxt->pfds_lock);
}

void handle_client_read(cxt_t* cxt, int client_fd) {
    pthread_mutex_lock(&cxt->pfds_lock);
    int bytes_recv = -1;
    int idx = -1;
    for (int i = 0; i < cxt->fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    }
    char buf[MAX_REQUEST_SIZE];
    if (cxt->clients[idx].is_ssl == NOT_TLS) {
        bytes_recv = recv_message(client_fd, buf, MAX_REQUEST_SIZE - 1);

        if (bytes_recv == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            pthread_mutex_unlock(&cxt->pfds_lock);
            return;
        }

        if (bytes_recv == 0) {
            pthread_mutex_unlock(&cxt->pfds_lock);
            close_connection(cxt, client_fd);
            return;
        }

    } else if (cxt->clients[idx].is_ssl == HANDSHAKING) {
        int r = SSL_accept(cxt->clients[idx].ssl);

        if (r == 1) {
            cxt->clients[idx].is_ssl = ESTABLISHED;
            cxt->pfds[idx].events = POLLIN;
        } else {
            int err = SSL_get_error(cxt->clients[idx].ssl, r);
            
            if (err == SSL_ERROR_WANT_READ) {
                cxt->pfds[idx].events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                cxt->pfds[idx].events = POLLOUT;
            } else {
                pthread_mutex_unlock(&cxt->pfds_lock);
                close_connection(cxt, client_fd);
                return;
            }
        }
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    } else if (cxt->clients[idx].is_ssl == ESTABLISHED) {
        bytes_recv = SSL_read(cxt->clients[idx].ssl, buf, MAX_REQUEST_SIZE - 1);

        if (bytes_recv <= 0) {
            int err = SSL_get_error(cxt->clients[idx].ssl, bytes_recv);
            if (err == SSL_ERROR_WANT_READ) {
                cxt->pfds[idx].events |= POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                cxt->pfds[idx].events |= POLLOUT;
            } else {
                pthread_mutex_unlock(&cxt->pfds_lock);
                close_connection(cxt, client_fd);
                return;
            }
            pthread_mutex_unlock(&cxt->pfds_lock);
            return;
        }
    } else { 
        pthread_mutex_unlock(&cxt->pfds_lock); 
        close_connection(cxt, client_fd);
        return;
    }
    
    pthread_mutex_unlock(&cxt->pfds_lock);

    if (bytes_recv > 0) {
        buf[bytes_recv] = '\0';
        job_t* j = malloc(sizeof(job_t));
        if (!j) { 
            perror("malloc job"); 
            return; 
        }
        j->fd = client_fd;
        j->data = malloc((size_t)bytes_recv);
        if (!j->data) { 
            free(j); 
            perror("malloc job data");
            return; 
        }
        memcpy(j->data, buf, (size_t)bytes_recv);
        j->data_len = (size_t)bytes_recv;
        j->next = NULL;

        pthread_mutex_lock(&cxt->q->lock);
        q_push(cxt->q, j);
        pthread_cond_signal(&cxt->q->cond);
        pthread_mutex_unlock(&cxt->q->lock);
    }

}

void handle_client_send(cxt_t* cxt, int client_fd) {
    pthread_mutex_lock(&cxt->pfds_lock);

    int idx = -1;
    for (int i = 0; i < cxt->fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    }

    client_t *c = &cxt->clients[idx];
    if (!c->write_buf || c->write_len == 0) {
        cxt->pfds[idx].events &= ~POLLOUT;
        cxt->pfds[idx].events |= POLLIN;
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    }

    ssize_t to_send = c->write_len - c->write_send;
    ssize_t sent = -1;
    if (cxt->clients[idx].is_ssl == NOT_TLS) {
        sent = send_message(c->fd, c->write_buf + c->write_send, to_send);
        if (sent <= 0) {
            if (sent == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                pthread_mutex_unlock(&cxt->pfds_lock);
                return;
            }
            if (c->write_buf) { free(c->write_buf); c->write_buf = NULL; }
            cxt->pfds[idx] = cxt->pfds[cxt->fdcount - 1];
            cxt->clients[idx] = cxt->clients[cxt->fdcount - 1];
            cxt->fdcount--;
            pthread_mutex_unlock(&cxt->pfds_lock);
            close(client_fd);
            return;
        }
    } else if (cxt->clients[idx].is_ssl == HANDSHAKING) {
        int r = SSL_accept(cxt->clients[idx].ssl);

        if (r == 1) {
            cxt->clients[idx].is_ssl = ESTABLISHED;
            cxt->pfds[idx].events = POLLIN;
        } else {
            int err = SSL_get_error(cxt->clients[idx].ssl, r);
            
            if (err == SSL_ERROR_WANT_READ) {
                cxt->pfds[idx].events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                cxt->pfds[idx].events = POLLOUT;
            } else {
                pthread_mutex_unlock(&cxt->pfds_lock);
                close_connection(cxt, client_fd);
                return;
            }
        }
        pthread_mutex_unlock(&cxt->pfds_lock);
        return;
    } else if (cxt->clients[idx].is_ssl == ESTABLISHED) {
        sent = SSL_write(cxt->clients[idx].ssl, c->write_buf + c->write_send, to_send);
        if (sent <= 0) {
            int err = SSL_get_error(cxt->clients[idx].ssl, sent);
            if (err == SSL_ERROR_WANT_READ) {
                cxt->pfds[idx].events |= POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                cxt->pfds[idx].events |= POLLOUT;
            } else {
                pthread_mutex_unlock(&cxt->pfds_lock);
                close_connection(cxt, client_fd);
                return;
            }
            pthread_mutex_unlock(&cxt->pfds_lock);
            return;
        }
    } else {
        pthread_mutex_unlock(&cxt->pfds_lock);
        close_connection(cxt, client_fd);
        return;
    }

    c->write_send += sent;
    if (c->write_send >= c->write_len) {
        free(c->write_buf);
        c->write_buf = NULL;
        c->write_len = 0;
        c->write_send = 0;
        cxt->pfds[idx].events &= ~POLLOUT;
        cxt->pfds[idx].events |= POLLIN;
    }

    pthread_mutex_unlock(&cxt->pfds_lock);
}


void close_connection(cxt_t* cxt, int client_fd) {
    pthread_mutex_lock(&cxt->pfds_lock);
    for (int i = 0; i < cxt->fdcount; i++) {
        if (cxt->pfds[i].fd == client_fd) {
            if (cxt->clients[i].ssl != NULL) {
                SSL_shutdown(cxt->clients[i].ssl);
                SSL_free(cxt->clients[i].ssl);
            }
            if (cxt->clients[i].write_buf) { free(cxt->clients[i].write_buf); cxt->clients[i].write_buf = NULL; }
            close(client_fd);
            cxt->pfds[i] = cxt->pfds[cxt->fdcount - 1];
            cxt->clients[i] = cxt->clients[cxt->fdcount - 1];
            cxt->fdcount--;
            break;
        }
    }
    pthread_mutex_unlock(&cxt->pfds_lock);
}
