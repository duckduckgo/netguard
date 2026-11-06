/*
 * Checks when DNS sessions close and when a query starts a new session, for DNS clients that send several queries
 * from the same socket.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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
    uint16_t pending;

    printf("Closing once every query is answered\n");
    pending = 0;
    dns_session_query_sent(&pending);
    check("one query, answered: close", dns_session_answer_received(&pending), 1);

    pending = 0;
    dns_session_query_sent(&pending); // A
    dns_session_query_sent(&pending); // AAAA
    check("two queries at once, first answer: keep open", dns_session_answer_received(&pending), 0);
    check("two queries at once, second answer: close", dns_session_answer_received(&pending), 1);

    pending = 0;
    check("answer without a query (eg. duplicate): close", dns_session_answer_received(&pending), 1);
    check("pending queries never go below 0", pending, 0);

    pending = UINT16_MAX;
    dns_session_query_sent(&pending);
    check("pending queries never overflow", pending, UINT16_MAX);

    printf("Starting a new session for a query from a finished one\n");
    check("DNS session closing", dns_session_finished(53, UDP_FINISHING), 1);
    check("DNS session closed", dns_session_finished(53, UDP_CLOSED), 1);
    check("DNS session active: reuse it", dns_session_finished(53, UDP_ACTIVE), 0);
    check("DNS session blocked: keep dropping", dns_session_finished(53, UDP_BLOCKED), 0);
    check("other UDP session closed: keep dropping", dns_session_finished(443, UDP_CLOSED), 0);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
