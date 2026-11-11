#ifndef UDP_H
#define UDP_H

#include <stdint.h>

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

#define DNS_SESSION_MAX_PENDING 8

// The IDs of the DNS queries waiting for an answer
struct dns_pending {
    uint16_t ids[DNS_SESSION_MAX_PENDING];
    uint8_t count;
};

#endif // UDP_H
