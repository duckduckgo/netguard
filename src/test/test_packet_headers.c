/*
 * Checks the parsing of the IPv4 and TCP header lengths, which come from the packet and so can't be trusted.
 *
 * Built with AddressSanitizer: each packet is copied into an exact-size heap allocation so that any read past
 * its end aborts the test.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../netguard/include/packet_headers.h"

static int failures = 0;

static void check(const char *name, size_t actual, size_t expected) {
    int ok = actual == expected;
    printf("  %-56s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    expected %zu, got %zu\n", expected, actual);
        failures++;
    }
}

// IPv4 packet of length bytes whose header length field is ihl (32-bit words)
static size_t ip4(uint8_t ihl, size_t length) {
    uint8_t *pkt = calloc(length ? length : 1, 1);
    if (length > 0) pkt[0] = (uint8_t) (0x40 | ihl);
    size_t result = ip4_header_length(pkt, length);
    free(pkt);
    return result;
}

// TCP segment of length bytes whose data offset field is doff (32-bit words)
static size_t tcp(uint8_t doff, size_t length) {
    uint8_t *seg = calloc(length ? length : 1, 1);
    if (length > 12) seg[12] = (uint8_t) (doff << 4);
    size_t result = tcp_header_length(seg, length);
    free(seg);
    return result;
}

int main() {
    printf("IPv4 header length\n");
    check("no options", ip4(5, 40), 20);
    check("with options", ip4(6, 40), 24);
    check("largest header", ip4(15, 60), 60);
    check("header fills the packet", ip4(6, 24), 24);
    check("header longer than the packet", ip4(15, 40), 0);
    check("header shorter than the fixed header (ihl 4)", ip4(4, 40), 0);
    check("header length 0", ip4(0, 40), 0);
    check("packet shorter than the fixed header", ip4(5, 19), 0);
    check("empty packet", ip4(5, 0), 0);

    printf("TCP header length\n");
    check("no options", tcp(5, 20), 20);
    check("with options", tcp(10, 100), 40);
    check("largest header", tcp(15, 60), 60);
    check("header longer than the segment", tcp(15, 40), 0);
    check("header shorter than the fixed header (doff 4)", tcp(4, 40), 0);
    check("header length 0", tcp(0, 40), 0);
    check("segment shorter than the fixed header", tcp(5, 19), 0);
    check("empty segment", tcp(5, 0), 0);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
