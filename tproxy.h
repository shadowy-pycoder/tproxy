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

#define HOST            "0.0.0.0"
#define PORT            8888
#define MAX_CONNECTIONS 4092
#define SERVER_WORKERS  100

/* Create a TCP server listening on address specified by host and port parameters.
 *
 * This function either returns a valid file descriptor or exits with non-zero status code
 */
int create_tproxy_server(char *host, int port);
void usage(void);
#endif // TPROXY_H
