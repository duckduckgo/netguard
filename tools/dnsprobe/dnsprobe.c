/*
 * Sends several DNS queries from one UDP socket, the way some DNS libraries do, and reports which answers come back
 * and how long they take.
 *
 * Test 1: A and AAAA queries sent together.
 * Test 2: A query, then the AAAA query from the same socket once the A one is answered.
 *
 * Missing answers are retried from the same socket every RETRY_MS, up to RETRIES times.
 *
 * Usage: dnsprobe [server ip] [name]   (defaults: 8.8.8.8 example.com)
 * Exits with 0 when every answer arrived without retries, 1 otherwise, 2 if the probe couldn't send at all.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RETRY_MS 2000
#define RETRIES 3

struct query {
    const char *label;
    uint16_t id;
    uint8_t buf[512];
    size_t len;
    long long sent_at;
    long long answered_ms; // -1 while waiting, -2 when given up
    int retries;
};

static int send_errors = 0;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static size_t build_query(uint8_t *buf, uint16_t id, const char *name, uint16_t qtype) {
    size_t pos = 0;
    buf[pos++] = id >> 8;
    buf[pos++] = id & 0xFF;
    buf[pos++] = 0x01; // recursion desired
    buf[pos++] = 0x00;
    buf[pos++] = 0;
    buf[pos++] = 1; // 1 question
    memset(buf + pos, 0, 6);
    pos += 6;
    const char *label = name;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t) (dot - label) : strlen(label);
        buf[pos++] = (uint8_t) len;
        memcpy(buf + pos, label, len);
        pos += len;
        label += len + (dot ? 1 : 0);
    }
    buf[pos++] = 0;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0;
    buf[pos++] = 1; // class IN
    return pos;
}

static void init_query(struct query *q, const char *label, uint16_t id, uint16_t qtype, const char *name) {
    memset(q, 0, sizeof(*q));
    q->label = label;
    q->id = id;
    q->len = build_query(q->buf, id, name, qtype);
    q->answered_ms = -1;
}

static void send_query(int sock, struct query *q) {
    if (send(sock, q->buf, q->len, 0) < 0) {
        printf("    send %s failed: %s\n", q->label, strerror(errno));
        send_errors++;
    }
    q->sent_at = now_ms();
}

// Waits for the answers to queries[0..n), retrying missing ones from the same socket. Returns how many were answered.
static int wait_answers(int sock, struct query *queries, int n, long long start) {
    for (;;) {
        int waiting = 0;
        long long deadline = 0;
        for (int i = 0; i < n; i++) {
            if (queries[i].answered_ms == -1) {
                waiting++;
                long long d = queries[i].sent_at + RETRY_MS;
                if (deadline == 0 || d < deadline) deadline = d;
            }
        }
        if (waiting == 0) break;

        long long wait = deadline - now_ms();
        struct pollfd pfd = {sock, POLLIN, 0};
        if (poll(&pfd, 1, wait > 0 ? (int) wait : 0) > 0) {
            uint8_t resp[1500];
            ssize_t got = recv(sock, resp, sizeof(resp), 0);
            if (got < 12) continue;
            uint16_t id = (uint16_t) ((resp[0] << 8) | resp[1]);
            for (int i = 0; i < n; i++) {
                struct query *q = &queries[i];
                if (q->id == id && q->answered_ms == -1) {
                    q->answered_ms = now_ms() - start;
                    printf("    %-4s answered after %5lld ms (rcode %d, %d answers, %d retries)\n",
                           q->label, q->answered_ms, resp[3] & 0x0F, (resp[6] << 8) | resp[7], q->retries);
                }
            }
            continue;
        }

        // Timed out: retry the missing ones from the same socket, or give up
        for (int i = 0; i < n; i++) {
            struct query *q = &queries[i];
            if (q->answered_ms != -1 || now_ms() < q->sent_at + RETRY_MS) continue;
            if (q->retries < RETRIES) {
                q->retries++;
                send_query(sock, q);
            } else {
                printf("    %-4s NO ANSWER after %d retries (%lld ms)\n", q->label, q->retries, now_ms() - start);
                q->answered_ms = -2;
            }
        }
    }

    int answered = 0;
    for (int i = 0; i < n; i++) {
        if (queries[i].answered_ms >= 0) answered++;
    }
    return answered;
}

static int open_socket(const char *server) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    if (inet_pton(AF_INET, server, &addr.sin_addr) != 1) {
        printf("invalid IPv4 server address %s\n", server);
        exit(2);
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("socket/connect failed: %s\n", strerror(errno));
        exit(2);
    }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(sock, (struct sockaddr *) &local, &len);
    printf("  local port %u\n", ntohs(local.sin_port));
    return sock;
}

static const char *verdict(int lost, int slow, const char *lost_message) {
    if (send_errors) return "ERROR: couldn't send, the network is blocked for this app";
    if (lost) return lost_message;
    if (slow) return "SLOW: needed a retry";
    return "OK";
}

int main(int argc, char **argv) {
    const char *server = argc > 1 ? argv[1] : "8.8.8.8";
    const char *name = argc > 2 ? argv[2] : "example.com";
    srand((unsigned) now_ms());
    int problems = 0;

    printf("Test 1: A and AAAA for %s sent together from one socket to %s\n", name, server);
    {
        int sock = open_socket(server);
        struct query q[2];
        init_query(&q[0], "A", (uint16_t) rand(), 1, name);
        init_query(&q[1], "AAAA", (uint16_t) (q[0].id + 1), 28, name);
        long long start = now_ms();
        send_query(sock, &q[0]);
        send_query(sock, &q[1]);
        int answered = wait_answers(sock, q, 2, start);
        int slow = q[0].retries > 0 || q[1].retries > 0;
        printf("  -> %s\n", verdict(answered < 2, slow, "FAIL: an answer was lost"));
        problems += answered < 2 || slow;
        close(sock);
    }

    printf("Test 2: A for %s, then AAAA from the same socket once A is answered\n", name);
    {
        int sock = open_socket(server);
        struct query q[2];
        init_query(&q[0], "A", (uint16_t) rand(), 1, name);
        init_query(&q[1], "AAAA", (uint16_t) (q[0].id + 1), 28, name);
        long long start = now_ms();
        send_query(sock, &q[0]);
        int first = wait_answers(sock, &q[0], 1, start);
        long long second_start = now_ms();
        send_query(sock, &q[1]);
        int second = wait_answers(sock, &q[1], 1, second_start);
        int slow = q[0].retries > 0 || q[1].retries > 0;
        printf("  -> %s\n", verdict(!first || !second, slow, "FAIL: the second query on the same socket got no answer"));
        problems += !first || !second || slow;
        close(sock);
    }

    if (send_errors) {
        printf("\nThe probe couldn't send any query: the network is blocked for this app\n");
        return 2;
    }
    printf("\n%s\n", problems ? "Problems found" : "All answers arrived without retries");
    return problems ? 1 : 0;
}
