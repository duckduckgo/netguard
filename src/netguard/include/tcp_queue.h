#ifndef TCP_QUEUE_H
#define TCP_QUEUE_H

#include <stdint.h>
#include <string.h>
#include "memory.h"

/**
 * Data an app sent on a TCP connection that hasn't been forwarded to the server yet: segments ordered by sequence
 * number. Data is forwarded from the first segment only, and only once it starts where the forwarded data ends
 * (remote_seq), so that the server receives the app's bytes in order.
 *
 * Segments can overlap: an app retransmits the same bytes in segments of other lengths, eg. a short segment that fit
 * a small window, then a longer one from the same sequence number that also covers the next segment. Once data is
 * forwarded, tcp_queue_next drops or trims what other segments hold of it. Without that a segment starting before
 * remote_seq stays first, never matches it, and the upload stalls until the server gives up.
 */
struct segment {
    uint32_t seq;
    uint16_t len;
    uint16_t sent;
    int psh;
    uint8_t *data;
    struct segment *next;
};

enum tcp_queue_result {
    TCP_QUEUE_ADDED,
    // Starts before remote_seq, so it was forwarded already
    TCP_QUEUE_FORWARDED,
    // A segment with the same sequence number and length is queued
    TCP_QUEUE_DUPLICATE,
    // A segment with the same sequence number is queued and was shorter: it now holds this one's data
    TCP_QUEUE_LONGER,
    // A segment with the same sequence number is queued and is longer, so it already holds this one's data
    TCP_QUEUE_SHORTER,
};

// Whether sequence number a comes before b (RFC 1982)
static inline int tcp_seq_before(uint32_t a, uint32_t b) {
    return (int32_t) (a - b) < 0;
}

static inline enum tcp_queue_result tcp_queue_add(struct segment **queue, uint32_t remote_seq,
                                                  uint32_t seq, const uint8_t *data, uint16_t len, int psh) {
    if (tcp_seq_before(seq, remote_seq))
        return TCP_QUEUE_FORWARDED;

    struct segment *p = NULL;
    struct segment *s = *queue;
    while (s != NULL && tcp_seq_before(s->seq, seq)) {
        p = s;
        s = s->next;
    }

    if (s == NULL || tcp_seq_before(seq, s->seq)) {
        struct segment *n = ng_malloc(sizeof(struct segment), "tcp segment");
        n->seq = seq;
        n->len = len;
        n->sent = 0;
        n->psh = psh;
        n->data = ng_malloc(len, "tcp segment");
        memcpy(n->data, data, len);
        n->next = s;
        if (p == NULL)
            *queue = n;
        else
            p->next = n;
        return TCP_QUEUE_ADDED;
    }

    if (s->len == len)
        return TCP_QUEUE_DUPLICATE;
    // Shortening the segment could leave less data than was sent of it already
    if (s->len > len)
        return TCP_QUEUE_SHORTER;

    // The same bytes, plus more: what was sent of the segment stays sent
    ng_free(s->data, __FILE__, __LINE__);
    s->len = len;
    s->data = ng_malloc(len, "tcp segment");
    memcpy(s->data, data, len);
    return TCP_QUEUE_LONGER;
}

// Removes the first segment, once it's fully sent
static inline void tcp_queue_pop(struct segment **queue) {
    struct segment *s = *queue;
    *queue = s->next;
    ng_free(s->data, __FILE__, __LINE__);
    ng_free(s, __FILE__, __LINE__);
}

/**
 * The segment to forward next: the first one, when it starts where the forwarded data ends. NULL when the queue is
 * empty or still waits for the app to send the data that comes first.
 *
 * Drops the segments holding only data forwarded already, and trims the one holding some of it.
 */
static inline struct segment *tcp_queue_next(struct segment **queue, uint32_t remote_seq) {
    struct segment *s;
    while ((s = *queue) != NULL && tcp_seq_before(s->seq, remote_seq)) {
        if (!tcp_seq_before(remote_seq, s->seq + s->len)) {
            tcp_queue_pop(queue);
        } else {
            uint16_t forwarded = (uint16_t) (remote_seq - s->seq);
            memmove(s->data, s->data + forwarded, s->len - forwarded);
            s->seq = remote_seq;
            s->len -= forwarded;
            s->sent = s->sent > forwarded ? s->sent - forwarded : 0;
        }
    }
    return s != NULL && s->seq == remote_seq ? s : NULL;
}

static inline void tcp_queue_clear(struct segment **queue) {
    while (*queue != NULL)
        tcp_queue_pop(queue);
}

#endif // TCP_QUEUE_H
