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
#ifndef TPROXY_H
#define TPROXY_H

/* Create a TCP server listening on address specified by host and port parameters.
 *
 * This function either returns a valid file descriptor or exits with non-zero status code
 */
#include <netinet/in.h>
#include <semaphore.h>

#define ADDR_SIZE 50

int create_tproxy_server(char *host, int port);

void usage(void);

typedef struct {
    struct sockaddr_in raw;
    int port;
    char addr_str[ADDR_SIZE];
} Address;

typedef struct {
    int sock;
    Address addr;
} Client;

Client *client_new(struct sockaddr_in addr, int sock);
void client_destroy(Client *);

void handle_tproxy_connection(Client *);
void read_write(Client *src, Client *dst, sem_t *sem);

#endif // TPROXY_H
