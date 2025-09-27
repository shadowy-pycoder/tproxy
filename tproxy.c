#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/*
 * Create a socket
 * Set options like SO_REUSADDR and IP_TRANSPARENT
 * Bind socket to address
 * Create an infinite loop to accept connections (use threads or async IO)
 * Forward data to destination address
 * Get answer from destination and forward it to source
 */

int main(int argc, char** argv)
{
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        printf("Creating socket failed: %s\n", strerror(errno));
    }
    int enable = 1;
    if (setsockopt(server_sock, IPPROTO_IP, IP_TRANSPARENT, (const char*)&enable, sizeof(enable)) < 0) {
        printf("Setting option failed: %s\n", strerror(errno));
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(enable)) < 0) {
        printf("Setting option failed: %s\n", strerror(errno));
    }
    return 0;
}
