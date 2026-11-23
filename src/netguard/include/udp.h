#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <time.h>

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

#define DNS_SESSION_MAX_PENDING 8
#define DNS_SESSION_MAX_BLOCKED 8
#define DNS_BLOCKED_RETRY_TIMEOUT 60 // seconds, as long as a finished session used to drop everything

// The IDs of the DNS queries waiting for an answer
struct dns_pending {
    uint16_t ids[DNS_SESSION_MAX_PENDING];
    uint8_t count;
};

// The IDs of the last DNS queries whose answer was blocked, and when: a ring, an unused slot has time 0
struct dns_blocked {
    uint16_t ids[DNS_SESSION_MAX_BLOCKED];
    time_t at[DNS_SESSION_MAX_BLOCKED];
    uint8_t next; // the slot the next blocked ID goes in
};

#endif // UDP_H
