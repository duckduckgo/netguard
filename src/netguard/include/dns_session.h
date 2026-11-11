#ifndef DNS_SESSION_H
#define DNS_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include "udp.h"

/**
 * DNS sessions (UDP to port 53) are closed once answered, to avoid running out of file descriptors with one
 * socket per query. Some DNS clients send several queries from the same socket, though, either one after the
 * other or at the same time (eg. IPv4 and IPv6 addresses). So a session keeps the IDs of the queries waiting for
 * an answer and only closes once there are none left, and a query from the socket of a closed session starts a new
 * one. IDs, not a count, so that a retry of a lost query, which has the same ID, isn't waited for twice.
 */

// The ID at the start of a DNS message, or -1 if it's too short to have one
static inline int dns_message_id(const uint8_t *data, size_t len) {
    return len < 2 ? -1 : (data[0] << 8) | data[1];
}

// Records a query sent to the DNS server. When too many are waiting, the query isn't recorded, and the session
// closes once the recorded ones are answered: a later query from the same socket then starts a new session.
static inline void dns_session_query_sent(struct dns_pending *pending, int id) {
    if (id < 0) {
        return;
    }
    for (int i = 0; i < pending->count; i++) {
        if (pending->ids[i] == id) {
            return;
        }
    }
    if (pending->count < DNS_SESSION_MAX_PENDING) {
        pending->ids[pending->count++] = (uint16_t) id;
    }
}

// Records an answer from the DNS server, returns whether the session can now be closed
static inline int dns_session_answer_received(struct dns_pending *pending, int id) {
    for (int i = 0; i < pending->count; i++) {
        if (pending->ids[i] == id) {
            pending->ids[i] = pending->ids[--pending->count];
            break;
        }
    }
    return pending->count == 0;
}

/**
 * Whether a DNS session is closing or closed, and so a new query from the same app socket should start a new
 * session instead of being dropped as part of this one.
 */
static inline int dns_session_finished(uint16_t dest_port, uint8_t state) {
    return dest_port == 53 && (state == UDP_FINISHING || state == UDP_CLOSED);
}

#endif // DNS_SESSION_H
