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
#ifndef TPROXY_EPOLL_H
#define TPROXY_EPOLL_H

/* Create a TCP server listening on address specified by host and port parameters.
 *
 * This function either returns a valid file descriptor or exits with non-zero status code
 */
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define ADDR_SIZE 50
#define BUF_SIZE  (32 * 1024)

typedef struct {
    struct sockaddr_in raw;
    int port;
    char addr_str[ADDR_SIZE];
} Address;

typedef struct {
    char data[BUF_SIZE];
    int size;
    int offset;
} Buffer;

typedef struct {
    int sock;
    bool connected;
    bool closed;
    Address addr;
    Buffer *buf;
} Client;

typedef struct {
    Client *src;
    Client *dst;
} Tunnel;

typedef enum {
    SRC_SOCKET,
    DST_SOCKET
} SocketSide;

typedef struct {
    Tunnel *tun;
    SocketSide side;
} Connection;

Client *client_new(struct sockaddr_in addr, int sock);
void client_destroy(Client *);
Tunnel *tunnel_new(Client *src, Client *dst);
void tunnel_destroy(Tunnel *);
Connection *connection_new(Tunnel *tun, SocketSide side);
void connection_destroy(Connection *);
bool setup_tproxy_connection(int epfd, Client *c);
int setnonblocking(int fd);
int epoll_add(int epfd, Connection *conn, uint32_t events);
int epoll_mod(int epfd, Connection *conn, uint32_t events);
int epoll_del(int epfd, Connection *conn);
void handle_client_events(int epfd, Connection *conn, uint32_t events);
void *handle_server_epoll(void *ssock);
bool handle_write(Client *src, Client *dst);
bool handle_read(Client *src);
void connection_cleanup(int epfd, Connection *conn, Client *src, Client *dst, Tunnel *tun);
#endif // TPROXY_EPOLL_H
