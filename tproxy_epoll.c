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
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "tproxy_epoll.h"

#define MAX_EVENTS 500

int setnonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void *handle_server_epoll(void *ssock)
{
    struct epoll_event *events = malloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (events == NULL) exit(EXIT_FAILURE);
    int server_sock = *(int *)ssock;
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        printf("Creating epoll file descriptor failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    Client *c = (Client *)malloc(sizeof(Client));
    if (c == NULL) exit(EXIT_FAILURE);
    c->sock = server_sock;
    Tunnel *tun = tunnel_new(c, NULL);
    Connection *conn = connection_new(tun, SRC_SOCKET);
    if (epoll_add(epfd, conn, EPOLLIN | EPOLLET) < 0) {
        printf("Adding to epoll failed: %s\n", strerror(errno));
        connection_destroy(conn);
        tunnel_destroy(tun);
        exit(EXIT_FAILURE);
    }
    int nready;
    int fd;
    while (true) {
        nready = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nready < 0) {
            printf("Waiting for epoll failed: %s\n", strerror(errno));
            connection_destroy(conn);
            tunnel_destroy(tun);
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < nready; i++) {
            if (events[i].events == 0) continue;

            Connection *conn = (Connection *)events[i].data.ptr;
            switch (conn->side) {
            case SRC_SOCKET:
                fd = conn->tun->src->sock;
                break;
            case DST_SOCKET:
                fd = conn->tun->dst->sock;
                break;
            default:
                printf("Unknown socket side %d\n", conn->side);
                exit(EXIT_FAILURE);
            }

            if (fd == server_sock) {
                if (!(events[i].events & EPOLLIN)) {
                    printf("Server is not ready to accept connections %d\n", events[i].events);
                    continue;
                }
                while (true) {
                    struct sockaddr_in client_addr = { 0 };
                    client_addr.sin_family = AF_INET;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_sock = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        printf("Accept connection failed: %s\n", strerror(errno));
                        break;
                    }
                    if (setnonblocking(client_sock) < 0) {
                        printf("Set nonblockong failed: %s\n", strerror(errno));
                        close(client_sock);
                        break;
                    }
                    Client *c = client_new(client_addr, client_sock);
                    if (!setup_tproxy_connection(epfd, c)) {
                        break;
                    }
                    pid_t tid = gettid();
                    printf("[%d] Accepted connection from %s:%d\n", tid, c->addr.addr_str, c->addr.port);
                }
            } else {
                handle_client_events(epfd, conn, events[i].events);
            }
        }
    }
    return NULL;
}

int epoll_add(int epfd, Connection *conn, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = conn;
    ev.events = events;
    switch (conn->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_ADD, conn->tun->src->sock, &ev);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_ADD, conn->tun->dst->sock, &ev);
    default:
        printf("Unknown socket side %d\n", conn->side);
        return -1;
    }
}

int epoll_mod(int epfd, Connection *conn, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = conn;
    ev.events = events;
    switch (conn->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_MOD, conn->tun->src->sock, &ev);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_MOD, conn->tun->dst->sock, &ev);
    default:
        printf("Unknown socket side %d\n", conn->side);
        return -1;
    }
}

int epoll_del(int epfd, Connection *conn)
{
    switch (conn->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_DEL, conn->tun->src->sock, NULL);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_DEL, conn->tun->dst->sock, NULL);
    default:
        printf("Unknown socket side %d\n", conn->side);
        return -1;
    }
}

bool setup_tproxy_connection(int epfd, Client *c)
{
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(dst_addr);
    Client *dst_client;
    Tunnel *tun;

    if (getsockname(c->sock, (struct sockaddr *)&dst_addr, &addr_len) == 0) {
        int dst_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (dst_sock < 0) {
            printf("Creating socket failed: %s\n", strerror(errno));
            client_destroy(c);
            return false;
        }
        dst_client = client_new(dst_addr, dst_sock);
        printf("Destination address is %s:%d\n", dst_client->addr.addr_str, dst_client->addr.port);
        tun = tunnel_new(c, dst_client);
        int enable = 1;
        if (setsockopt(dst_client->sock, IPPROTO_IP, IP_TRANSPARENT, (const char *)&enable, sizeof(enable)) < 0) {
            printf("Setting IP_TRANSPARENT option for destination failed: %s\n", strerror(errno));
            tunnel_destroy(tun);
            return false;
        }
        if (bind(dst_client->sock, (struct sockaddr *)&c->addr.raw, sizeof(c->addr.raw)) < 0) {
            printf("Binding to destination address failed: %s\n", strerror(errno));
            tunnel_destroy(tun);
            return false;
        }
        if (connect(dst_client->sock, (struct sockaddr *)&dst_addr, addr_len) < 0) {
            if (errno != EINPROGRESS) {
                printf("Connection to destination failed %s\n", strerror(errno));
                tunnel_destroy(tun);
                return false;
            } else {
                tun->dst->connected = false;
            }
        } else {
            tun->dst->connected = true;
        }
        Connection *conn1 = connection_new(tun, SRC_SOCKET);
        if (epoll_add(epfd, conn1, EPOLLIN | EPOLLOUT | EPOLLET) < 0) {
            printf("Adding to epoll failed: %s\n", strerror(errno));
            connection_destroy(conn1);
            tunnel_destroy(tun);
            return false;
        }
        Connection *conn2 = connection_new(tun, DST_SOCKET);
        if (epoll_add(epfd, conn2, EPOLLIN | EPOLLOUT | EPOLLET) < 0) {
            printf("Adding to epoll failed: %s\n", strerror(errno));
            if (epoll_del(epfd, conn2) < 0) {
                printf("Removing from epoll failed: %s\n", strerror(errno));
            }
            connection_destroy(conn1);
            connection_destroy(conn2);
            tunnel_destroy(tun);
            return false;
        }
    } else {
        printf("Failed getting destination %s\n", strerror(errno));
        client_destroy(c);
        return false;
    }
    return true;
}

void handle_client_events(int epfd, Connection *conn, uint32_t events)
{
    (void)epfd;
    Client *sc, *dc;
    (void)dc;
    switch (conn->side) {
    case SRC_SOCKET:
        sc = conn->tun->src;
        dc = conn->tun->dst;
        break;
    case DST_SOCKET:
        sc = conn->tun->dst;
        dc = conn->tun->src;
        break;
    default:
        printf("Unknown socket side %d\n", conn->side);
        exit(EXIT_FAILURE);
    }
    if (events & EPOLLOUT) {
        // handle connection logic
        if (!(sc->connected)) {
            int err;
            socklen_t len = sizeof(err);
            if (getsockopt(sc->sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                printf("connect failed: %s\n", strerror(err));
                // TODO: delete conn from events
                // TODO: close conn here
                return;
            }
            sc->connected = true;
        }
        // check for wbuff of other side
        // if any data, write until EWOULDBLOCK | EAGAIN
        // write any pending data to the sc
        // if other side is closed already, close tunnel
    } else if (events & EPOLLIN) {
        // close tunnel if other side is closed
        // read data into buffer
    } else if ((events & EPOLLHUP) || (events & EPOLLRDHUP) || (events & EPOLLERR)) {
    }
    return;
}

Client *client_new(struct sockaddr_in addr, int sock)
{
    Client *c = (Client *)malloc(sizeof(Client));
    if (c == NULL) exit(EXIT_FAILURE);
    c->sock = sock;
    c->addr.raw = addr;
    c->connected = true;
    c->closed = false;
    char *temp_ip = inet_ntoa(addr.sin_addr);
    memset(c->addr.addr_str, 0, ADDR_SIZE);
    memcpy(c->addr.addr_str, temp_ip, strlen(temp_ip));
    int client_port = ntohs(addr.sin_port);
    c->addr.port = client_port;
    c->rbuf = (Buffer *)malloc(sizeof(Buffer));
    if (c->rbuf == NULL) exit(EXIT_FAILURE);
    memset(c->rbuf, 0, sizeof(Buffer));
    c->wbuf = (Buffer *)malloc(sizeof(Buffer));
    if (c->wbuf == NULL) exit(EXIT_FAILURE);
    memset(c->wbuf, 0, sizeof(Buffer));
    return c;
}

void client_destroy(Client *c)
{
    if (c == NULL)
        return;
    printf("Closing connection to %s:%d\n", c->addr.addr_str, c->addr.port);
    if (close(c->sock) < 0) {
        printf("Closing socket failed for %s:%d: %s\n", c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        printf("Connection to %s:%d closed\n", c->addr.addr_str, c->addr.port);
    }
    free(c->rbuf);
    free(c->wbuf);
    free(c);
}

Tunnel *tunnel_new(Client *src, Client *dst)
{
    Tunnel *tun = malloc(sizeof(Tunnel));
    if (tun == NULL) exit(EXIT_FAILURE);
    tun->src = src;
    tun->dst = dst;
    return tun;
}

void tunnel_destroy(Tunnel *tun)
{
    client_destroy(tun->src);
    client_destroy(tun->dst);
    free(tun);
}

Connection *connection_new(Tunnel *tun, SocketSide side)
{
    Connection *conn = malloc(sizeof(Connection));
    if (tun == NULL) exit(EXIT_FAILURE);
    conn->tun = tun;
    conn->side = side;
    return conn;
}

void connection_destroy(Connection *conn)
{
    free(conn);
}
