#ifndef DNS_SESSION_H
#define DNS_SESSION_H

#include <stdint.h>
#include "udp.h"

/**
 * DNS sessions (UDP to port 53) are closed once answered, to avoid running out of file descriptors with one
 * socket per query. Some DNS clients send several queries from the same socket, though, either one after the
 * other or at the same time (eg. IPv4 and IPv6 addresses). So a session counts the queries waiting for an answer
 * and only closes once there are none left, and a query from the socket of a closed session starts a new one.
 */

// Records a query sent to the DNS server
static inline void dns_session_query_sent(uint16_t *pending_queries) {
    if (*pending_queries < UINT16_MAX) {
        (*pending_queries)++;
    }
}

// Records an answer from the DNS server, returns whether the session can now be closed
static inline int dns_session_answer_received(uint16_t *pending_queries) {
    if (*pending_queries > 0) {
        (*pending_queries)--;
    }
    return *pending_queries == 0;
}

/**
 * Whether a DNS session is closing or closed, and so a new query from the same app socket should start a new
 * session instead of being dropped as part of this one.
 */
static inline int dns_session_finished(uint16_t dest_port, uint8_t state) {
    return dest_port == 53 && (state == UDP_FINISHING || state == UDP_CLOSED);
}

#endif // DNS_SESSION_H
