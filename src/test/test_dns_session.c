/*
 * Checks when DNS sessions close and when a query starts a new session, for DNS clients that send several queries
 * from the same socket.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../netguard/include/dns_session.h"

static int failures = 0;

static void check(const char *name, int actual, int expected) {
    int ok = actual == expected;
    printf("  %-64s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    expected %d, got %d\n", expected, actual);
        failures++;
    }
}

int main() {
    struct dns_pending pending;

    printf("Closing once every query is answered\n");
    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, 1);
    check("one query, answered: close", dns_session_answer_received(&pending, 1), 1);

    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, 1); // A
    dns_session_query_sent(&pending, 2); // AAAA
    check("two queries at once, first answer: keep open", dns_session_answer_received(&pending, 1), 0);
    check("two queries at once, second answer: close", dns_session_answer_received(&pending, 2), 1);

    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, 1);
    dns_session_query_sent(&pending, 2);
    check("two queries answered out of order: keep open", dns_session_answer_received(&pending, 2), 0);
    check("two queries answered out of order: close", dns_session_answer_received(&pending, 1), 1);

    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, 1);
    dns_session_query_sent(&pending, 1); // retry of a lost query
    check("query and its retry, one answer: close", dns_session_answer_received(&pending, 1), 1);

    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, 1);
    check("answer to another query: keep open", dns_session_answer_received(&pending, 2), 0);
    check("answer to another query: query still waiting", pending.count, 1);

    memset(&pending, 0, sizeof(pending));
    check("answer without a query (eg. duplicate): close", dns_session_answer_received(&pending, 1), 1);

    memset(&pending, 0, sizeof(pending));
    dns_session_query_sent(&pending, -1);
    check("query too short to have an ID: not waited for", pending.count, 0);

    memset(&pending, 0, sizeof(pending));
    for (int id = 0; id <= DNS_SESSION_MAX_PENDING; id++) {
        dns_session_query_sent(&pending, id);
    }
    check("too many queries: the extra one isn't waited for", pending.count, DNS_SESSION_MAX_PENDING);

    printf("Reading the ID of a DNS message\n");
    const uint8_t message[] = {0xab, 0xcd, 0x01, 0x00};
    check("ID of a message", dns_message_id(message, sizeof(message)), 0xabcd);
    check("message too short", dns_message_id(message, 1), -1);

    printf("Starting a new session for a query from a finished one\n");
    check("DNS session closing", dns_session_finished(53, UDP_FINISHING), 1);
    check("DNS session closed", dns_session_finished(53, UDP_CLOSED), 1);
    check("DNS session active: reuse it", dns_session_finished(53, UDP_ACTIVE), 0);
    check("DNS session blocked: keep dropping", dns_session_finished(53, UDP_BLOCKED), 0);
    check("other UDP session closed: keep dropping", dns_session_finished(443, UDP_CLOSED), 0);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
