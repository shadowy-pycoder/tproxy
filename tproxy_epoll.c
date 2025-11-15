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
#include <pthread.h>
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
    Connection *conn = connection_new(c, NULL);
    Tunnel *tun = tunnel_new(conn, SRC_SOCKET);
    if (epoll_add(epfd, tun, EPOLLIN | EPOLLET) < 0) {
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

            Tunnel *tun = (Tunnel *)events[i].data.ptr;
            switch (tun->side) {
            case SRC_SOCKET:
                fd = tun->conn->src->sock;
                break;
            case DST_SOCKET:
                fd = tun->conn->dst->sock;
                break;
            default:
                printf("Unknown socket side %d\n", tun->side);
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
                handle_client_events(epfd, tun, events[i].events);
            }
        }
    }
    return NULL;
}

int epoll_add(int epfd, Tunnel *tun, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = tun;
    ev.events = events;
    switch (tun->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_ADD, tun->conn->src->sock, &ev);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_ADD, tun->conn->dst->sock, &ev);
    default:
        printf("Unknown socket side %d\n", tun->side);
        return -1;
    }
}

int epoll_mod(int epfd, Tunnel *tun, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = tun;
    ev.events = events;
    switch (tun->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_MOD, tun->conn->src->sock, &ev);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_MOD, tun->conn->dst->sock, &ev);
    default:
        printf("Unknown socket side %d\n", tun->side);
        return -1;
    }
}

int epoll_del(int epfd, Tunnel *tun)
{
    switch (tun->side) {
    case SRC_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_DEL, tun->conn->src->sock, NULL);
    case DST_SOCKET:
        return epoll_ctl(epfd, EPOLL_CTL_DEL, tun->conn->dst->sock, NULL);
    default:
        printf("Unknown socket side %d\n", tun->side);
        return -1;
    }
}

bool setup_tproxy_connection(int epfd, Client *c)
{
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(dst_addr);
    Client *dst_client;
    Connection *conn;

    if (getsockname(c->sock, (struct sockaddr *)&dst_addr, &addr_len) == 0) {
        int dst_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (dst_sock < 0) {
            printf("Creating socket failed: %s\n", strerror(errno));
            client_destroy(c);
            return false;
        }
        dst_client = client_new(dst_addr, dst_sock);
        printf("Destination address is %s:%d\n", dst_client->addr.addr_str, dst_client->addr.port);
        conn = connection_new(c, dst_client);
        int enable = 1;
        if (setsockopt(dst_client->sock, IPPROTO_IP, IP_TRANSPARENT, (const char *)&enable, sizeof(enable)) < 0) {
            printf("Setting IP_TRANSPARENT option for destination failed: %s\n", strerror(errno));
            connection_destroy(conn);
            return false;
        }
        if (bind(dst_client->sock, (struct sockaddr *)&c->addr.raw, sizeof(c->addr.raw)) < 0) {
            printf("Binding to destination address failed: %s\n", strerror(errno));
            connection_destroy(conn);
            return false;
        }
        if (connect(dst_client->sock, (struct sockaddr *)&dst_addr, addr_len) < 0) {
            if (errno != EINPROGRESS) {
                printf("Connection to destination failed %s\n", strerror(errno));
                connection_destroy(conn);
                return false;
            } else {
                conn->dst->connected = false;
            }
        } else {
            conn->dst->connected = true;
        }
        Tunnel *tun1 = tunnel_new(conn, SRC_SOCKET);
        if (epoll_add(epfd, tun1, EPOLLIN | EPOLLOUT | EPOLLET) < 0) {
            printf("Adding to epoll failed: %s\n", strerror(errno));
            connection_destroy(conn);
            tunnel_destroy(tun1);
            return false;
        }
        Tunnel *tun2 = tunnel_new(conn, DST_SOCKET);
        if (epoll_add(epfd, tun2, EPOLLIN | EPOLLOUT | EPOLLET) < 0) {
            printf("Adding to epoll failed: %s\n", strerror(errno));
            if (epoll_del(epfd, tun1) < 0) {
                printf("Removing from epoll failed: %s\n", strerror(errno));
            }
            connection_destroy(conn);
            tunnel_destroy(tun1);
            tunnel_destroy(tun2);
            return false;
        }
    } else {
        printf("Failed getting destination %s\n", strerror(errno));
        client_destroy(c);
        return false;
    }
    return true;
}

void handle_client_events(int epfd, Tunnel *tun, uint32_t events)
{
    /*
     * Check for EPOLLIN
     * Check for EPOLLOUT (if not connected, check for error, if connected handle write
     * int err;
        socklen_t len = sizeof(err);
        if (getsockopt(remote_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            // Connection failed
            fprintf(stderr, "connect failed: %s\n", strerror(err));
            close_tunnel(t);
            return;
}

     * Check for EPOLLHUP/EPOLLRDHUP/EPOLLERR
     */
    (void)tun;
    (void)epfd;
    if (events & EPOLLIN) {
        // close connection if other side is closed
        // read data into buffer
    } else if (events & EPOLLOUT) {
        // write data
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

Connection *connection_new(Client *src, Client *dst)
{
    Connection *conn = malloc(sizeof(Connection));
    if (conn == NULL) exit(EXIT_FAILURE);
    conn->src = src;
    conn->dst = dst;
    return conn;
}

void connection_destroy(Connection *conn)
{
    client_destroy(conn->src);
    client_destroy(conn->dst);
    free(conn);
}

Tunnel *tunnel_new(Connection *conn, SocketSide side)
{
    Tunnel *tun = malloc(sizeof(Tunnel));
    if (tun == NULL) exit(EXIT_FAILURE);
    tun->conn = conn;
    tun->side = side;
    return tun;
}

void tunnel_destroy(Tunnel *tun)
{
    free(tun);
}
