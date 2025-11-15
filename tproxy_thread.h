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
#ifndef TPROXY_THREAD_H
#define TPROXY_THREAD_H

#include <netinet/in.h>
#include <semaphore.h>
#include <stdint.h>

#define ADDR_SIZE 50
#define BUF_SIZE  (32 * 1024)

typedef struct {
    struct sockaddr_in raw;
    int port;
    char addr_str[ADDR_SIZE];
} Address;

typedef struct {
    int sock;
    Address addr;
} Client;

Client *thread_client_new(struct sockaddr_in addr, int sock);
void thread_client_destroy(Client *);
void handle_tproxy_connection(Client *);
void read_write(Client *src, Client *dst, sem_t *sem);
void *handle_server_thread(void *);

#endif // TPROXY_THREAD_H
