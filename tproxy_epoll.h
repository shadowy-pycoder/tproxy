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

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>

#define ADDR_SIZE     50
#define BUF_SIZE      (32 * 1024)
#define READ_TIMEOUT  10
#define WRITE_TIMEOUT 10
#define EPOLL_TIMEOUT (30 * 1000)
#define SND_BUF_SIZE  (1024 * 1024 * 2)
#define RECV_BUF_SIZE (1024 * 1024 * 2)

typedef const struct sockaddr_in SockAddr;

typedef struct {
    int port;
    char addr_str[ADDR_SIZE];
} Address;

typedef struct {
    char data[BUF_SIZE];
    int size;
    int offset;
} Buffer;

typedef struct Tunnel Tunnel;
typedef struct Connection Connection;

typedef struct Socket {
    int fd;
    Connection *c;
} Socket;

struct Connection {
    Socket *sock;
    Socket *rtsock;
    Socket *wtsock;
    bool connected;
    bool rclosed;
    bool wclosed;
    Address addr;
    Buffer *buf;
    Tunnel *tun;
    Connection *other;
    uint64_t written;
};

struct Tunnel {
    Connection src;
    Connection dst;
};

typedef struct EpollServerArgs {
    int *ssock;
    int *esock;
} EpollServerArgs;

bool tunnel_new(Tunnel *tun, int src, int dst, SockAddr src_addr, SockAddr dst_addr);
void tunnel_destroy(Tunnel *tun);
bool connection_new(Connection *c, int sock, Tunnel *tun, SockAddr addr);
void connection_destroy(Connection *c);
bool setup_tproxy_connection(int epfd, int src_sock, SockAddr src_addr);
int set_timeout(int tsock, int sec);
int setnonblocking(int fd);
bool sockets_register(int epfd, Connection *src, Connection *dst);
int epoll_add(int epfd, Socket *sock, uint32_t events);
int epoll_mod(int epfd, Socket *sock, uint32_t events);
int epoll_del(int epfd, Socket *sock);
void handle_client_events(Socket *sock, uint32_t events, bool shutting_down);
bool handle_write(Connection *src, Connection *dst);
bool handle_read(Connection *src);
void *handle_server_epoll(void *args);
void connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready);
#endif // TPROXY_EPOLL_H
