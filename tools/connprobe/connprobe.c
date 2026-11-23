/*
 * Opens TCP connections to an address one after the other, waiting up to TIMEOUT_MS for each, and reports how many
 * connected, failed or timed out.
 *
 * Usage: connprobe [address] [port] [count]   (defaults: 2001:4860:4860::8888 443 50)
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_MS 1500

int main(int argc, char **argv) {
    const char *address = argc > 1 ? argv[1] : "2001:4860:4860::8888";
    int port = argc > 2 ? atoi(argv[2]) : 443;
    int count = argc > 3 ? atoi(argv[3]) : 50;

    struct sockaddr_storage addr;
    socklen_t addr_len;
    memset(&addr, 0, sizeof(addr));
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &addr;
    struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr;
    if (inet_pton(AF_INET6, address, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        addr_len = sizeof(*addr6);
    } else if (inet_pton(AF_INET, address, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        addr_len = sizeof(*addr4);
    } else {
        printf("invalid address %s\n", address);
        return 2;
    }

    int connected = 0, failed = 0, timed_out = 0;
    for (int i = 0; i < count; i++) {
        int sock = socket(addr.ss_family, SOCK_STREAM, 0);
        if (sock < 0) {
            printf("socket error: %s\n", strerror(errno));
            return 2;
        }
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

        int err = 0;
        if (connect(sock, (struct sockaddr *) &addr, addr_len) < 0) {
            err = errno;
            if (err == EINPROGRESS) {
                struct pollfd pfd = {sock, POLLOUT, 0};
                if (poll(&pfd, 1, TIMEOUT_MS) <= 0) {
                    err = ETIMEDOUT;
                } else {
                    socklen_t len = sizeof(err);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                }
            }
        }
        if (err == 0) {
            connected++;
        } else if (err == ETIMEDOUT) {
            timed_out++;
        } else {
            if (failed == 0) printf("connect error: %s\n", strerror(err));
            failed++;
        }
        close(sock);
    }
    printf("%d connections to %s port %d: %d connected, %d failed, %d timed out\n",
           count, address, port, connected, failed, timed_out);
    return 0;
}
