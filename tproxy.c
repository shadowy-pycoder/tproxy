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
        char buf[BUF_SIZE] = { 0 };
        struct sockaddr_in client_addr = { 0 };
        client_addr.sin_family = AF_INET;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            printf("Accept connection failed: %s\n", strerror(errno));
        }
        char* temp_ip = inet_ntoa(client_addr.sin_addr);
        char client_ip[100] = { 0 };
        memcpy(client_ip, temp_ip, strlen(temp_ip));
        int client_port = ntohs(client_addr.sin_port);
        printf("Accepted connection from %s:%d\n", client_ip, client_port);
        struct sockaddr_in dst_addr = { 0 };
        dst_addr.sin_family = AF_INET;
        addr_len = sizeof(dst_addr);
        char dst_ip[100] = { 0 };
        int dst_port;
        if (getsockname(client_sock, (struct sockaddr*)&dst_addr, &addr_len) == 0) {
            temp_ip = inet_ntoa(dst_addr.sin_addr);
            memcpy(dst_ip, temp_ip, strlen(temp_ip));
            dst_port = ntohs(dst_addr.sin_port);
            printf("Destination address is %s:%d\n", dst_ip, dst_port);
        } else {
            printf("Failed getting destination %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        }
        int nr = read(client_sock, buf, sizeof(buf));
        if (nr < 0) {
            printf("Reading message failed %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        } else {
            printf("Read %d bytes from client %s:%d\n", nr, client_ip, client_port);
        }

        int proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (proxy_sock < 0) {
            printf("Creating socket failed: %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        }
        if (connect(proxy_sock, (struct sockaddr*)&dst_addr, addr_len) < 0) {
            printf("Connection to destination failed %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            if (close(proxy_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        } else {
            printf("Connected to destination %s:%d\n", dst_ip, dst_port);
        }
        int nw = write(proxy_sock, buf, nr);
        if (nw < 0) {
            printf("Writing message failed %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            if (close(proxy_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        } else {
            printf("Written %d bytes to destination %s:%d\n", nr, dst_ip, dst_port);
        }
        nr = read(proxy_sock, buf, sizeof(buf));
        if (nr < 0) {
            printf("Reading message failed %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            if (close(proxy_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            continue;
        } else {
            printf("Read %d bytes from destination %s:%d\n", nr, dst_ip, dst_port);
        }

        nw = write(client_sock, buf, nr);
        if (nw < 0) {
            printf("Writing message failed %s\n", strerror(errno));
            if (close(client_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
            if (close(proxy_sock) < 0) {
                printf("Closing socket failed: %s\n", strerror(errno));
            }
        } else {
            printf("Written %d bytes to client %s:%d\n", nr, client_ip, client_port);
        }

        if (close(client_sock) < 0) {
            printf("Closing socket failed: %s\n", strerror(errno));
        }
        if (close(proxy_sock) < 0) {
            printf("Closing socket failed: %s\n", strerror(errno));
        }
        break;
    }
    return 0;
}
