/*
 * Copyright (C) 2025 shadowy-pycoder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "tproxy_epoll.h"

#define MAX_EVENTS 500

int setnonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_timeout(int tsock, int sec)
{
    struct itimerspec new_value = { 0 };
    new_value.it_value.tv_sec = sec;
    return timerfd_settime(tsock, 0, &new_value, NULL);
}

void *handle_server_epoll(void *args)
{
    pid_t tid = gettid();
    struct epoll_event *events = malloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (events == NULL) exit(EXIT_FAILURE);

    EpollServerArgs *esargs = (EpollServerArgs *)args;
    int server_sock = *esargs->ssock;
    int esock = *esargs->esock;
    free(esargs->ssock);
    free(esargs);
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        printf("ERROR: [%d] Creating epoll file descriptor failed %s\n", tid, strerror(errno));
        free(events);
        exit(EXIT_FAILURE);
    }

    Connection *sc = (Connection *)malloc(sizeof(Connection));
    if (sc == NULL) exit(EXIT_FAILURE);
    sc->sock = (Socket *)malloc(sizeof(Socket));
    sc->sock->fd = server_sock;
    sc->sock->c = sc;
    if (epoll_add(epfd, sc->sock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding server socket to epoll failed: %s\n", tid, strerror(errno));
        close(server_sock);
        free(events);
        free(sc->sock);
        free(sc);
        exit(EXIT_FAILURE);
    }
    Connection *ec = (Connection *)malloc(sizeof(Connection));
    if (ec == NULL) exit(EXIT_FAILURE);
    ec->sock = (Socket *)malloc(sizeof(Socket));
    ec->sock->fd = esock;
    ec->sock->c = ec;
    if (epoll_add(epfd, ec->sock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding event socket to epoll failed: %s\n", tid, strerror(errno));
        free(events);
        free(ec->sock);
        free(ec);
        exit(EXIT_FAILURE);
    }
    int nready;
    bool shutting_down = false;
    while (true) {
        nready = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        if (nready < 0) {
            printf("ERROR: [%d] Waiting for epoll failed: %s\n", tid, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (shutting_down && nready == 0) break;
        for (int i = 0; i < nready; i++) {
            if (events[i].events == 0) continue;
            Socket *sock = (Socket *)events[i].data.ptr;
            if (sock->fd == server_sock && !shutting_down) {
                if (!(events[i].events & EPOLLIN)) {
                    printf("INFO: [%d] Server is not ready to accept connections %d\n", tid, events[i].events);
                    continue;
                }
                while (true) {
                    struct sockaddr_in client_addr = { 0 };
                    client_addr.sin_family = AF_INET;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_sock = accept(sock->fd, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        printf("ERROR: [%d] Accept connection failed: %s\n", tid, strerror(errno));
                        break;
                    }
                    if (!setup_tproxy_connection(epfd, client_sock, client_addr)) {
                        break;
                    }
                }
            } else if (sock->fd == esock) {
                shutting_down = true;
                if (epoll_del(epfd, sc->sock) < 0) {
                    printf("ERROR: [%d] Removing server socket from epoll failed: %s\n", tid, strerror(errno));
                }
                if (epoll_del(epfd, ec->sock) < 0) {
                    printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
                }
                close(server_sock);
                free(sc->sock);
                free(sc);
                free(ec->sock);
                free(ec);
            } else {
                handle_client_events(sock, events[i].events, shutting_down);
                connection_cleanup(epfd, sock, events, i, nready);
            }
        }
    }
#ifdef DEBUG
    printf("DEBUG: [%d] server closed\n", tid);
#endif
    free(events);
    pthread_exit(NULL);
    return NULL;
}

bool setup_tproxy_connection(int epfd, int src_sock, SockAddr src_addr)
{
    pid_t tid = gettid();
    if (setnonblocking(src_sock) < 0) {
        printf("ERROR: [%d] Set nonblockong failed: %s\n", tid, strerror(errno));
        close(src_sock);
        return false;
    }
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(dst_addr);
    if (getsockname(src_sock, (struct sockaddr *)&dst_addr, &addr_len) == 0) {
        int dst_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (dst_sock < 0) {
            printf("ERROR: [%d] Creating socket failed: %s\n", tid, strerror(errno));
            close(src_sock);
            return false;
        }
        int send_buffer_size = SND_BUF_SIZE;
        int recv_buffer_size = RECV_BUF_SIZE;
        if (setsockopt(dst_sock, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) < 0) {
            printf("ERROR: [%d] Setting SO_SNDBUF option for destination failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (setsockopt(dst_sock, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size)) < 0) {
            printf("ERROR: [%d] Setting SO_RCVBUF option for destination failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        int enable = 1;
        if (setsockopt(src_sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: [%d] Setting SOL_SOCKET option for source failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (setsockopt(src_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: [%d] Setting TCP_NODELAY option for source failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (setsockopt(dst_sock, IPPROTO_IP, IP_TRANSPARENT, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: [%d] Setting IP_TRANSPARENT option for destination failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (setsockopt(dst_sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: [%d] Setting SOL_SOCKET option for source failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (setsockopt(dst_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: [%d] Setting TCP_NODELAY option for source failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (bind(dst_sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
            printf("ERROR: [%d] Binding to destination address failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        Tunnel *tun = (Tunnel *)malloc(sizeof(Tunnel));
        if (tun == NULL) {
            printf("ERROR: [%d] Allocating memory for tunnel failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (!tunnel_new(tun, src_sock, dst_sock, src_addr, dst_addr)) {
            printf("ERROR: [%d] tunnel creation failed: %s\n", tid, strerror(errno));
            close(src_sock);
            close(dst_sock);
            return false;
        }
        if (connect(dst_sock, (struct sockaddr *)&dst_addr, addr_len) < 0) {
            if (errno != EINPROGRESS) {
                printf("ERROR: [%d] Connection to destination failed %s\n", tid, strerror(errno));
                tunnel_destroy(tun);
                return false;
            } else {
                tun->dst.connected = false;
            }
        } else {
            tun->dst.connected = true;
        }
        if (!sockets_register(epfd, &tun->src, &tun->dst)) {
            tunnel_destroy(tun);
            return false;
        }
        printf("INFO: [%d] New connection %s:%d <-> %s:%d\n", tid, tun->src.addr.addr_str,
            tun->src.addr.port, tun->dst.addr.addr_str, tun->dst.addr.port);
    } else {
        printf("ERROR: [%d] Failed getting destination %s\n", tid, strerror(errno));
        close(src_sock);
        return false;
    }
    return true;
}

bool sockets_register(int epfd, Connection *src, Connection *dst)
{
    pid_t tid = gettid();
    if (set_timeout(src->rtsock->fd, READ_TIMEOUT) < 0) {
        printf("ERROR: [%d] setting read timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    if (set_timeout(src->wtsock->fd, WRITE_TIMEOUT) < 0) {
        printf("ERROR: [%d] setting write timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    if (set_timeout(dst->rtsock->fd, READ_TIMEOUT) < 0) {
        printf("ERROR: [%d] setting read timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    if (set_timeout(dst->wtsock->fd, WRITE_TIMEOUT) < 0) {
        printf("ERROR: [%d] setting write timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    if (epoll_add(epfd, src->sock, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding client socket to epoll failed: %s\n", tid, strerror(errno));
        return false;
    }
    if (epoll_add(epfd, src->rtsock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding read timeout socket to epoll failed: %s\n", tid, strerror(errno));
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        return false;
    }
    if (epoll_add(epfd, src->wtsock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding write timeout socket to epoll failed: %s\n", tid, strerror(errno));
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        return false;
    }
    if (epoll_add(epfd, dst->sock, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding client socket to epoll failed: %s\n", tid, strerror(errno));
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->wtsock) < 0) {
            printf("ERROR: [%d] Removing write timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        return false;
    }
    if (epoll_add(epfd, dst->rtsock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding read timeout socket to epoll failed: %s\n", tid, strerror(errno));
        if (epoll_del(epfd, dst->sock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->wtsock) < 0) {
            printf("ERROR: [%d] Removing write timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        return false;
    }
    if (epoll_add(epfd, dst->wtsock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding write timeout socket to epoll failed: %s\n", tid, strerror(errno));
        if (epoll_del(epfd, dst->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, dst->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->wtsock) < 0) {
            printf("ERROR: [%d] Removing write timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        return false;
    }
    return true;
}

void handle_client_events(Socket *sock, uint32_t events, bool shutting_down)
{
    pid_t tid = gettid();
    Connection *src = sock->c;
    Connection *dst = sock->c->other;
    if ((events & EPOLLHUP) || (events & EPOLLERR)) {
        src->rclosed = true;
        src->wclosed = true;
        dst->rclosed = true;
        dst->wclosed = true;
        return;
    }
    if (shutting_down || (events & EPOLLRDHUP)) {
        if (!src->rclosed) handle_read(src);
        if (src->buf->size > 0 && !dst->wclosed) handle_write(src, dst);
        if (!dst->wclosed) {
            if (shutdown(dst->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
            }
            dst->wclosed = true;
        }
        src->rclosed = true;
        return;
    }
    bool read_timeout = sock->fd == src->rtsock->fd;
    bool write_timeout = sock->fd == src->wtsock->fd;
    if (read_timeout) {
#ifdef DEBUG
        printf("DEBUG: [%d] %s:%d read timeout\n", tid, src->addr.addr_str, src->addr.port);
#endif
        uint64_t exp;
        int res = read(src->rtsock->fd, &exp, sizeof(exp));
        (void)res;
        if (!src->rclosed) handle_read(src);
        if (src->buf->size > 0 && !dst->wclosed) handle_write(src, dst);
        src->rclosed = true;
        dst->wclosed = true;
        return;
    }
    if (write_timeout) {
#ifdef DEBUG
        printf("DEBUG: [%d] %s:%d write timeout\n", tid, src->addr.addr_str, src->addr.port);
#endif
        uint64_t exp;
        int res = read(src->wtsock->fd, &exp, sizeof(exp));
        (void)res;
        src->wclosed = true;
        dst->rclosed = true;
        return;
    }
    if (events & EPOLLIN) {
        if (src->rclosed || !handle_read(src)) {
            if (src->buf->size > 0 && !dst->wclosed) handle_write(src, dst);
            if (!dst->wclosed) {
                if (shutdown(dst->sock->fd, SHUT_WR) < 0) {
                    if (errno != ENOTCONN)
                        printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
                }
                dst->wclosed = true;
            }
            src->rclosed = true;
            return;
        }
        if (dst->connected && !dst->wclosed) {
            if (!handle_write(src, dst)) {
                if (shutdown(dst->sock->fd, SHUT_WR) < 0) {
                    if (errno != ENOTCONN)
                        printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
                }
                dst->wclosed = true;
                return;
            }
        }
    } else if (events & EPOLLOUT) {
        if (!src->connected) {
#ifdef DEBUG
            printf("DEBUG: [%d] Connecting %s:%d\n", tid, src->addr.addr_str, src->addr.port);
#endif
            int err;
            socklen_t len = sizeof(err);
            if (getsockopt(src->sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                printf("ERROR: [%d] Connect failed: %s\n", tid, strerror(err));
                src->rclosed = true;
                src->wclosed = true;
                dst->rclosed = true;
                dst->wclosed = true;
                return;
            }
            src->connected = true;
#ifdef DEBUG
            printf("DEBUG: [%d] Connected %s:%d\n", tid, src->addr.addr_str, src->addr.port);
#endif
        }
        if (dst->rclosed || !(handle_write(dst, src))) {
            if (shutdown(src->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
            }
            src->wclosed = true;
            dst->rclosed = true;
            return;
        }
    }
    return;
}

bool handle_read(Connection *src)
{
    pid_t tid = gettid();
    int buf_size = sizeof(src->buf->data);
    while (true) {
        int nr = read(src->sock->fd, src->buf->data + src->buf->size, buf_size - src->buf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) break;
            if (errno == EINTR) continue;
            printf("ERROR: [%d] Reading message from %s:%d failed: %s\n", tid, src->addr.addr_str, src->addr.port, strerror(errno));
            return false;
        } else if (nr == 0) {
#ifdef DEBUG
            printf("DEBUG: [%d] %s:%d:EOF\n", tid, src->addr.addr_str, src->addr.port);
#endif
            return false;
        } else {
            src->buf->size += nr;
            set_timeout(src->rtsock->fd, READ_TIMEOUT);
#ifdef DEBUG
            printf("DEBUG: [%d] Read %d bytes from client %s:%d\n", tid, nr, src->addr.addr_str, src->addr.port);
#endif
            if (src->buf->size >= buf_size) {
                break;
            }
        }
    }
    return true;
}

bool handle_write(Connection *src, Connection *dst)
{
    pid_t tid = gettid();
    while (true) {
        int nw = write(dst->sock->fd, src->buf->data + src->buf->offset, src->buf->size - src->buf->offset);
        if (nw < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) break;
            if (errno == EINTR) continue;
            printf("ERROR: [%d] Writing message %s:%d -> %s:%d failed: %s\n", tid, src->addr.addr_str, src->addr.port, dst->addr.addr_str, dst->addr.port, strerror(errno));
            return false;
        } else if (nw == 0) {
            break;
        } else {
            src->written += nw;
            src->buf->offset += nw;
            set_timeout(dst->wtsock->fd, WRITE_TIMEOUT);
#ifdef DEBUG
            printf("DEBUG: [%d] Written %d bytes %s:%d -> %s:%d\n", tid, nw, src->addr.addr_str, src->addr.port, dst->addr.addr_str, dst->addr.port);
#endif
            if (src->buf->offset >= src->buf->size) {
                src->buf->offset = 0;
                src->buf->size = 0;
                break;
            }
        }
    }
    return true;
}

void connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready)
{
    Connection *src = sock->c;
    Connection *dst = sock->c->other;
    if (src->rclosed && src->wclosed && dst->rclosed && dst->wclosed) {
        for (int i = idx + 1; i < nready; i++) {
            Socket *nsock = (Socket *)events[i].data.ptr;
            if (nsock->fd == src->sock->fd || nsock->fd == src->rtsock->fd || nsock->fd == src->wtsock->fd || nsock->fd == dst->sock->fd || nsock->fd == dst->rtsock->fd || nsock->fd == dst->wtsock->fd) return;
        }
        pid_t tid = gettid();
        if (epoll_del(epfd, src->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, src->wtsock) < 0) {
            printf("ERROR: [%d] Removing write timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, dst->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, dst->rtsock) < 0) {
            printf("ERROR: [%d] Removing read timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (epoll_del(epfd, dst->wtsock) < 0) {
            printf("ERROR: [%d] Removing write timeout socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (shutdown(src->sock->fd, SHUT_RDWR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: [%d] Shutting down failed for %s:%d: %s\n", tid, src->addr.addr_str, src->addr.port, strerror(errno));
        }
        if (shutdown(dst->sock->fd, SHUT_RDWR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: [%d] Shutting down failed for %s:%d: %s\n", tid, dst->addr.addr_str, dst->addr.port, strerror(errno));
        }
        if (src->written)
            printf("INFO: [%d] Written %lu bytes %s:%d -> %s:%d\n", tid, src->written, src->addr.addr_str, src->addr.port, dst->addr.addr_str, dst->addr.port);
        if (dst->written)
            printf("INFO: [%d] Written %lu bytes %s:%d -> %s:%d\n", tid, dst->written, dst->addr.addr_str, dst->addr.port, src->addr.addr_str, src->addr.port);
        tunnel_destroy(src->tun);
    }
}

int epoll_add(int epfd, Socket *sock, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = sock;
    ev.events = events;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, sock->fd, &ev);
}

int epoll_mod(int epfd, Socket *sock, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = sock;
    ev.events = events;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, sock->fd, &ev);
}

int epoll_del(int epfd, Socket *sock)
{
    return epoll_ctl(epfd, EPOLL_CTL_DEL, sock->fd, NULL);
}

bool tunnel_new(Tunnel *tun, int src, int dst, SockAddr src_addr, SockAddr dst_addr)
{
    memset(tun, 0, sizeof(*tun));
    if (!connection_new(&tun->src, src, tun, src_addr)) return false;
    if (!connection_new(&tun->dst, dst, tun, dst_addr)) return false;
    tun->src.other = &tun->dst;
    tun->dst.other = &tun->src;
    return true;
}

void tunnel_destroy(Tunnel *tun)
{
    connection_destroy(&tun->src);
    connection_destroy(&tun->dst);
    free(tun);
}

bool connection_new(Connection *c, int sock, Tunnel *tun, SockAddr addr)
{
    pid_t tid = gettid();
    memset(c, 0, sizeof(*c));
    c->sock = (Socket *)malloc(sizeof(Socket));
    if (c->sock == NULL) {
        printf("ERROR: [%d] Allocating memory for socket failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->sock->c = c;
    c->sock->fd = sock;
    if (c->sock->fd < 0) {
        printf("ERROR: [%d] Creating socket failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->rtsock = (Socket *)malloc(sizeof(Socket));
    if (c->rtsock == NULL) {
        printf("ERROR: [%d] Allocating memory for read timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->rtsock->c = c;
    c->rtsock->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (c->rtsock->fd < 0) {
        printf("ERROR: [%d] Creating read timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->wtsock = (Socket *)malloc(sizeof(Socket));
    if (c->wtsock == NULL) {
        printf("ERROR: [%d] Allocating memory for read timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->wtsock->c = c;
    c->wtsock->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (c->wtsock->fd < 0) {
        printf("ERROR: [%d] Creating write timeout failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->connected = true;
    c->rclosed = false;
    c->wclosed = false;
    char *temp_ip = inet_ntoa(addr.sin_addr);
    memset(c->addr.addr_str, 0, ADDR_SIZE);
    memcpy(c->addr.addr_str, temp_ip, strlen(temp_ip));
    c->addr.port = ntohs(addr.sin_port);
    c->buf = (Buffer *)malloc(sizeof(Buffer));
    if (c->buf == NULL) {
        printf("ERROR: [%d] Allocating memory for buffer failed: %s\n", tid, strerror(errno));
        return false;
    }
    memset(c->buf, 0, sizeof(Buffer));
    c->tun = tun;
    return true;
}

void connection_destroy(Connection *c)
{
    pid_t tid = gettid();
    printf("INFO: [%d] Closing connection %s:%d\n", tid, c->addr.addr_str, c->addr.port);
    if (close(c->sock->fd) < 0) {
        printf("ERROR: [%d] Closing socket failed for %s:%d: %s\n", tid, c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        printf("INFO: [%d] Connection to %s:%d closed\n", tid, c->addr.addr_str, c->addr.port);
    }
    close(c->rtsock->fd);
    close(c->wtsock->fd);
    free(c->sock);
    free(c->rtsock);
    free(c->wtsock);
    free(c->buf);
}
