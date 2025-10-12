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
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tproxy.h"

/*
 * Setup iptables and forwarding by running a shell script directly from C code
 * Create a socket
 * Set options like SO_REUSADDR and IP_TRANSPARENT
 * Bind socket to address
 * Listen on actual socket
 * Create an infinite loop to accept connections (use threads or async IO)
 * Connect to destination address
 * Forward data to destination address
 * Get answer from destination and forward it to source
 * On exit, try to restore iptables and other forwarding rules
 */

#define HOST            "0.0.0.0"
#define PORT            8888
#define MAX_CONNECTIONS INT_MAX
#define BUF_SIZE        (32 * 1024)

Client* client_new(struct sockaddr_in addr, int sock)
{
    Client* c = (Client*)malloc(sizeof(Client));
    c->sock = sock;
    char* temp_ip = inet_ntoa(addr.sin_addr);
    memset(c->addr.addr_str, 0, ADDR_SIZE);
    memcpy(c->addr.addr_str, temp_ip, strlen(temp_ip));
    int client_port = ntohs(addr.sin_port);
    c->addr.port = client_port;
    return c;
}

void client_destroy(Client* c)
{
    printf("Closing connection to %s:%d\n", c->addr.addr_str, c->addr.port);
    if (close(c->sock) < 0) {
        printf("Closing socket failed for %s:%d: %s\n", c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        printf("Connection to %s:%d closed\n", c->addr.addr_str, c->addr.port);
    }
    free(c);
}

void* read_write_thread(void* arg)
{
    ReadWrite* args = (ReadWrite*)arg;
    read_write(args->src, args->dst);
    pthread_exit(NULL);
    return NULL;
}

void read_write(Client* src, Client* dst)
{
    char buf[BUF_SIZE] = { 0 };
    while (true) {
        int nr = read(src->sock, buf, sizeof(buf));
        if (nr < 0) {
            printf("Reading message failed %s\n", strerror(errno));
            break;
        } else if (nr == 0) {
            printf("EOF: %s:%d\n", src->addr.addr_str, src->addr.port);
            break;
        } else {
            printf("Read %d bytes from client %s:%d\n", nr, src->addr.addr_str, src->addr.port);
        }
        int nw = write(dst->sock, buf, nr);
        if (nw < 0) {
            printf("Writing message failed %s\n", strerror(errno));
            break;
        } else {
            printf("Written %d bytes to destination %s:%d\n", nr, dst->addr.addr_str, dst->addr.port);
        }
    }
}

void* handle_tproxy_connection_thread(void* client)
{
    Client* c = (Client*)client;
    handle_tproxy_connection(c);
    pthread_exit(NULL);
    return NULL;
}

void handle_tproxy_connection(Client* c)
{
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(dst_addr);
    Client* dst_client;
    if (getsockname(c->sock, (struct sockaddr*)&dst_addr, &addr_len) == 0) {
        int dst_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (dst_sock < 0) {
            printf("Creating socket failed: %s\n", strerror(errno));
            client_destroy(c);
            return;
        }
        dst_client = client_new(dst_addr, dst_sock);
        printf("Destination address is %s:%d\n", dst_client->addr.addr_str, dst_client->addr.port);
        if (connect(dst_client->sock, (struct sockaddr*)&dst_addr, addr_len) < 0) {
            printf("Connection to destination failed %s\n", strerror(errno));
            client_destroy(c);
            client_destroy(dst_client);
            return;
        } else {
            printf("Connected to destination %s:%d\n", dst_client->addr.addr_str, dst_client->addr.port);
        }
    } else {
        printf("Failed getting destination %s\n", strerror(errno));
        client_destroy(c);
        return;
    }
    pthread_t thread;
    ReadWrite arg = { .src = c, .dst = dst_client };
    pthread_create(&thread, NULL, read_write_thread, (void*)&arg);
    read_write(dst_client, c);
    pthread_join(thread, NULL);
    client_destroy(c);
    client_destroy(dst_client);
}

int create_tproxy_server(char* host, int port)
{
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        printf("Creating socket failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int enable = 1;
    if (setsockopt(server_sock, IPPROTO_IP, IP_TRANSPARENT, (const char*)&enable, sizeof(enable)) < 0) {
        printf("Setting option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(enable)) < 0) {
        printf("Setting option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr = { 0 };
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) < 0) {
        printf("%s is not valid IP address\n", host);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Binding to address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        printf("Listening on address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("tproxy listening on %s:%d\n", host, port);
    return server_sock;
}

void usage(void)
{
    printf("Usage: tproxy <host> <port>\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    char* ip;
    int port;
    if (argc == 3) {
        ip = argv[1];
        port = atoi(argv[2]);
        if (port < 0 || port > 65535) {
            usage();
        }
    } else if (argc > 1) {
        usage();
    } else {
        ip = HOST;
        port = PORT;
    }
    int server_sock = create_tproxy_server(ip, port);
    while (true) {
        struct sockaddr_in client_addr = { 0 };
        client_addr.sin_family = AF_INET;
        socklen_t addr_len = sizeof(client_addr);

        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            printf("Accept connection failed: %s\n", strerror(errno));
        }
        Client* c = client_new(client_addr, client_sock);
        printf("Accepted connection from %s:%d\n", c->addr.addr_str, c->addr.port);
        pthread_t thread;
        pthread_detach(thread);
        pthread_create(&thread, NULL, handle_tproxy_connection_thread, c);
    }
    return 0;
}
