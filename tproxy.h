#ifndef TPROXY_H
#define TPROXY_H

/* Create a TCP server listening on address specified by host and port parameters.
 *
 * This function either returns a valid file descriptor or exits with non-zero status code
 */
int create_tproxy_server(char* host, int port);

void usage(void);

#endif // TPROXY_H
