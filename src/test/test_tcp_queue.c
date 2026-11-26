/*
 * Checks the queue of data an app sends on a TCP connection: whatever order and shape the app's segments arrive in,
 * including retransmissions that cover the same bytes with different lengths, the server must receive the app's bytes
 * once, in order, and without a stall.
 *
 * Forwarding is done the way tcp.c does it: from the segment tcp_queue_next returns, while what's left of it fits the
 * socket's free send buffer.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../netguard/include/tcp_queue.h"

#define STREAM_MAX 65536
// Free space in the socket's send buffer, as on a phone
#define SEND_BUFFER 524288

static int failures = 0;
static int allocations = 0;

void *ng_malloc(size_t size, const char *tag) {
    allocations++;
    return malloc(size);
}

void ng_free(void *ptr, const char *file, int line) {
    allocations--;
    free(ptr);
}

// The connection: what the app sent and what the server received
struct conn {
    uint32_t start; // sequence number of the stream's first byte
    uint32_t remote_seq; // next byte to forward
    struct segment *queue;
    uint8_t received[STREAM_MAX];
    uint32_t received_len;
};

static uint8_t stream_byte(uint32_t offset) {
    return (uint8_t) (offset * 7 + 3);
}

// The app sends the bytes from offset to offset + len of its stream
static void app_sends(struct conn *c, uint32_t offset, uint16_t len) {
    uint8_t data[STREAM_MAX];
    for (uint32_t i = 0; i < len; i++)
        data[i] = stream_byte(offset + i);
    tcp_queue_add(&c->queue, c->remote_seq, c->start + offset, data, len, 0);
}

// Forwards what the queue allows, sending at most max bytes to a socket with buffer bytes free
static void forward(struct conn *c, uint32_t max, uint32_t buffer) {
    struct segment *next;
    while (max > 0 && (next = tcp_queue_next(&c->queue, c->remote_seq)) != NULL &&
           next->len - next->sent < buffer) {
        uint32_t n = next->len - next->sent;
        if (n > max)
            n = max;
        memcpy(c->received + c->received_len, next->data + next->sent, n);
        c->received_len += n;
        next->sent += n;
        max -= n;
        if (next->sent == next->len) {
            c->remote_seq = next->seq + next->sent;
            tcp_queue_pop(&c->queue);
        }
    }
}

static void check(const char *name, struct conn *c, uint32_t expected_len) {
    int ok = c->received_len == expected_len && c->remote_seq == c->start + expected_len && c->queue == NULL;
    for (uint32_t i = 0; ok && i < c->received_len; i++)
        ok = c->received[i] == stream_byte(i);
    printf("  %-72s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    server received %u of %u bytes (%s), remote_seq at %u, queue %s\n",
               c->received_len, expected_len, c->received_len == expected_len ? "all" : "stalled",
               c->remote_seq - c->start, c->queue == NULL ? "empty" : "not empty");
        failures++;
    }
    tcp_queue_clear(&c->queue);
    if (allocations != 0) {
        printf("    %d allocation(s) leaked\n", allocations);
        failures++;
        allocations = 0;
    }
}

static void init(struct conn *c, uint32_t start) {
    memset(c, 0, sizeof(*c));
    c->start = start;
    c->remote_seq = start;
}

int main() {
    static struct conn c;

    init(&c, 1000);
    app_sends(&c, 0, 1000);
    app_sends(&c, 1000, 1000);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("In order", &c, 2000);

    init(&c, 1000);
    app_sends(&c, 1000, 1000);
    app_sends(&c, 0, 1000);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Out of order", &c, 2000);

    init(&c, 1000);
    app_sends(&c, 0, 1000);
    app_sends(&c, 0, 1000);
    app_sends(&c, 1000, 1000);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Retransmitted, same length", &c, 2000);

    // What froze uploads: a small segment, the next one, then a retransmission of the first covering part of the next
    init(&c, 1000);
    app_sends(&c, 0, 1024);
    app_sends(&c, 1024, 9216);
    app_sends(&c, 0, 9216);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Retransmitted longer, overlapping the next segment", &c, 10240);

    init(&c, 1000);
    app_sends(&c, 1000, 2000);
    app_sends(&c, 0, 1500);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Overlapping segments with different starts", &c, 3000);

    init(&c, 1000);
    app_sends(&c, 0, 1000);
    app_sends(&c, 200, 300);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Segment inside another", &c, 1000);

    // A partial send, eg. a nearly full socket buffer, then a shorter retransmission of the same segment
    init(&c, 1000);
    app_sends(&c, 0, 9216);
    forward(&c, 5000, SEND_BUFFER);
    app_sends(&c, 0, 1024);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Partly sent, then retransmitted shorter", &c, 9216);

    init(&c, 1000);
    app_sends(&c, 0, 9216);
    forward(&c, 5000, SEND_BUFFER);
    app_sends(&c, 0, 9216);
    app_sends(&c, 9216, 1000);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Partly sent, then retransmitted same length", &c, 10216);

    // Sequence numbers wrap around in the middle of the stream
    init(&c, UINT32_MAX - 500);
    app_sends(&c, 0, 1024);
    app_sends(&c, 1024, 9216);
    app_sends(&c, 0, 9216);
    forward(&c, UINT32_MAX, SEND_BUFFER);
    check("Retransmitted longer, sequence numbers wrapping around", &c, 10240);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
