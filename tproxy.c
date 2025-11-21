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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tproxy.h"
#ifdef USE_THREADS
#include "tproxy_thread.h"
#else
#include "tproxy_epoll.h"
#endif

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

int create_tproxy_server(char *host, int port)
{
#ifdef USE_THREADS
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
#else
    int server_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
#endif
    if (server_sock < 0) {
        printf("ERROR: Creating socket failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int enable = 1;
    if (setsockopt(server_sock, IPPROTO_IP, IP_TRANSPARENT, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr = { 0 };
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) < 0) {
        printf("ERROR: %s is not valid IP address\n", host);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("ERROR: Binding to address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        printf("ERROR: Listening on address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("INFO: tproxy listening on %s:%d\n", host, port);
    return server_sock;
}

void usage(void)
{
    printf("Usage: tproxy <host> <port>\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    char *ip;
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
    signal(SIGPIPE, SIG_IGN);
#ifdef USE_THREADS
    printf("INFO: Starting %d threading servers\n", SERVER_WORKERS);
#else
    printf("INFO: Starting %d epoll servers\n", SERVER_WORKERS);
#endif
    for (int i = 0; i < SERVER_WORKERS; i++) {
        int server_sock = create_tproxy_server(ip, port);
        pthread_t thread;
#ifdef USE_THREADS
        pthread_create(&thread, NULL, handle_server_thread, &server_sock);
#else
        pthread_create(&thread, NULL, handle_server_epoll, &server_sock);
#endif // USE_THREADS
        pthread_detach(thread);
    }
    pause();
    return 0;
}
