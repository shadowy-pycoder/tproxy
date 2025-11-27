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
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tproxy_thread.h"

typedef struct {
    Client *src;
    Client *dst;
    sem_t *sem;
} ReadWrite;

static void *handle_tproxy_connection_thread(void *);
static void *read_write_thread(void *);

void *read_write_thread(void *arg)
{
    ReadWrite *args = (ReadWrite *)arg;
    read_write(args->src, args->dst, args->sem);
    sem_trywait(args->sem);
    pthread_exit(NULL);
    return NULL;
}

void *handle_tproxy_connection_thread(void *client)
{
    Client *c = (Client *)client;
    handle_tproxy_connection(c);
    pthread_exit(NULL);
    return NULL;
}

void *handle_server_thread(void *ssock)
{
    int server_sock = *(int *)ssock;
    free(ssock);
    while (true) {
        struct sockaddr_in client_addr = { 0 };
        client_addr.sin_family = AF_INET;
        socklen_t addr_len = sizeof(client_addr);

        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            printf("ERROR: Accept connection failed: %s\n", strerror(errno));
            continue;
        }
        Client *src = thread_client_new(client_addr, client_sock);
        pid_t tid = gettid();
        printf("INFO: [%d] Accepted connection from %s:%d\n", tid, src->addr.addr_str, src->addr.port);
        pthread_t thread;
        pthread_create(&thread, NULL, handle_tproxy_connection_thread, src);
        pthread_detach(thread);
    }
    return NULL;
}

void handle_tproxy_connection(Client *src)
{
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(dst_addr);
    Client *dst;
    if (getsockname(src->sock, (struct sockaddr *)&dst_addr, &addr_len) == 0) {
        int dst_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (dst_sock < 0) {
            printf("ERROR: Creating socket failed: %s\n", strerror(errno));
            thread_client_destroy(src);
            return;
        }
        dst = thread_client_new(dst_addr, dst_sock);
        printf("INFO: Destination address is %s:%d\n", dst->addr.addr_str, dst->addr.port);
        int enable = 1;
        if (setsockopt(dst->sock, IPPROTO_IP, IP_TRANSPARENT, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: Setting IP_TRANSPARENT option for destination failed: %s\n", strerror(errno));
            thread_client_destroy(src);
            thread_client_destroy(dst);
            return;
        }
        if (bind(dst->sock, (struct sockaddr *)&src->addr.raw, sizeof(src->addr.raw)) < 0) {
            printf("ERROR: Binding to destination address failed: %s\n", strerror(errno));
            thread_client_destroy(src);
            thread_client_destroy(dst);
            return;
        }
        if (connect(dst->sock, (struct sockaddr *)&dst_addr, addr_len) < 0) {
            printf("ERROR: Connection to destination failed %s\n", strerror(errno));
            thread_client_destroy(src);
            thread_client_destroy(dst);
            return;
        } else {
            printf("INFO: Connected to destination %s:%d\n", dst->addr.addr_str, dst->addr.port);
        }
    } else {
        printf("ERROR: Failed getting destination %s\n", strerror(errno));
        thread_client_destroy(src);
        return;
    }
    // TODO: do something to connections made directly to tproxy address
    sem_t sem;
    sem_init(&sem, 0, 1);
    pthread_t thread1, thread2;
    ReadWrite arg1 = { .src = src, .dst = dst, .sem = &sem };
    ReadWrite arg2 = { .src = dst, .dst = src, .sem = &sem };
    pthread_create(&thread1, NULL, read_write_thread, (void *)&arg1);
    pthread_create(&thread2, NULL, read_write_thread, (void *)&arg2);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    sem_destroy(&sem);
    thread_client_destroy(src);
    thread_client_destroy(dst);
}

void read_write(Client *src, Client *dst, sem_t *sem)
{
    char *buf = malloc(sizeof(char) * BUF_SIZE);
    int value;
    unsigned long long int written = 0;
    while (true) {
        sem_getvalue(sem, &value);
        if (value == 0) break;

        int nr = read(src->sock, buf, sizeof(buf));
        if (nr < 0) {
            printf("ERROR: Reading message failed %s\n", strerror(errno));
            break;
        } else if (nr == 0) {
            printf("INFO: %s:%d:EOF\n", src->addr.addr_str, src->addr.port);
            break;
        } else {
#ifdef DEBUG
            printf("DEBUG: Read %d bytes from client %s:%d\n", nr, src->addr.addr_str, src->addr.port);
#endif
        }
        sem_getvalue(sem, &value);
        if (value == 0) break;

        int nw = write(dst->sock, buf, nr);
        if (nw < 0) {
            printf("ERROR: Writing message failed %s\n", strerror(errno));
            break;
        } else if (nw == 0) {
            break;
        } else {
            written += nw;
#ifdef DEBUG
            printf("DEBUG: Written %d bytes to destination %s:%d\n", nw, dst->addr.addr_str, dst->addr.port);
#endif
        }
    }
    if (written)
        printf("INFO: Written %llu bytes %s:%d -> %s:%d\n", written, src->addr.addr_str, src->addr.port, dst->addr.addr_str, dst->addr.port);
    if (shutdown(src->sock, SHUT_RDWR) < 0) {
        if (errno != ENOTCONN)
            printf("ERROR: Shutting down failed for %s:%d: %s\n", src->addr.addr_str, src->addr.port, strerror(errno));
    }
    free(buf);
}

Client *thread_client_new(struct sockaddr_in addr, int sock)
{
    Client *c = (Client *)malloc(sizeof(Client));
    if (c == NULL) exit(EXIT_FAILURE);
    c->sock = sock;
    c->addr.raw = addr;
    char *temp_ip = inet_ntoa(addr.sin_addr);
    memset(c->addr.addr_str, 0, ADDR_SIZE);
    memcpy(c->addr.addr_str, temp_ip, strlen(temp_ip));
    int client_port = ntohs(addr.sin_port);
    c->addr.port = client_port;
    return c;
}

void thread_client_destroy(Client *c)
{
    if (c == NULL)
        return;
    printf("INFO: Closing connection to %s:%d\n", c->addr.addr_str, c->addr.port);
    if (close(c->sock) < 0) {
        printf("ERROR: Closing socket failed for %s:%d: %s\n", c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        printf("INFO: Connection to %s:%d closed\n", c->addr.addr_str, c->addr.port);
    }
    free(c);
}
