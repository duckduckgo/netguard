
#include <poll.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include "platform.h"

static int is_event(int fd, short event) {
    struct pollfd p;
    p.fd = fd;
    p.events = event;
    p.revents = 0;
    int r = poll(&p, 1, 0);
    if (r < 0) {
        log_print(PLATFORM_LOG_PRIORITY_ERROR, "poll readable error %d: %s", errno, strerror(errno));
        return 0;
    } else if (r == 0)
        return 0;
    else
        return (p.revents & event);
}

int is_readable(int fd) {
    return is_event(fd, POLLIN);
}

int is_writable(int fd) {
    return is_event(fd, POLLOUT);
}

