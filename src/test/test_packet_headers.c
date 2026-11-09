/*
 * Checks the parsing of the IPv4 and TCP header lengths and TCP options, which come from the packet and so can't be
 * trusted.
 *
 * Built with AddressSanitizer: each packet is copied into an exact-size heap allocation so that any read past
 * its end aborts the test.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

struct syn_options {
    uint16_t mss;
    uint8_t ws;
};

// Parses length bytes of TCP options, starting from mss 1000 and ws 0
static struct syn_options options(const uint8_t *bytes, size_t length) {
    uint8_t *copy = malloc(length ? length : 1);
    memcpy(copy, bytes, length);
    struct syn_options result = {1000, 0};
    tcp_parse_syn_options(copy, length, &result.mss, &result.ws);
    free(copy);
    return result;
}

static void check_options(const char *name, const uint8_t *bytes, size_t length, uint16_t mss, uint8_t ws) {
    struct syn_options result = options(bytes, length);
    int ok = result.mss == mss && result.ws == ws;
    printf("  %-56s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    expected mss %u ws %u, got mss %u ws %u\n", mss, ws, result.mss, result.ws);
        failures++;
    }
}

int main() {
    // A parser stuck in a loop fails the test instead of hanging it
    alarm(10);

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

    printf("TCP SYN options\n");
    // MSS 1460, SACK permitted, timestamps, NOP, window scale 7: what Android sends
    const uint8_t android[] = {2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7};
    check_options("Android SYN", android, sizeof(android), 1460, 7);
    const uint8_t padded[] = {1, 1, 1, 2, 4, 0x05, 0xb4, 0, 3, 3, 7};
    check_options("padding, then end of options", padded, sizeof(padded), 1460, 0);
    check_options("no options", android, 0, 1000, 0);
    const uint8_t zero_length[] = {2, 4, 0x05, 0xb4, 8, 0, 3, 3, 7, 0, 0, 0};
    check_options("zero length option (used to loop forever)", zero_length, sizeof(zero_length), 1460, 0);
    const uint8_t length_one[] = {8, 1, 3, 3, 7, 0};
    check_options("length 1 option", length_one, sizeof(length_one), 1000, 0);
    const uint8_t past_end[] = {2, 4, 0x05, 0xb4, 8, 40, 0, 0};
    check_options("option running past the options", past_end, sizeof(past_end), 1460, 0);
    const uint8_t truncated_mss[] = {1, 1, 2, 4, 0x05};
    check_options("MSS cut off", truncated_mss, sizeof(truncated_mss), 1000, 0);
    const uint8_t kind_only[] = {1, 1, 1, 3};
    check_options("last option has no length byte", kind_only, sizeof(kind_only), 1000, 0);
    const uint8_t large_ws[] = {3, 3, 200, 0};
    check_options("window scale over 14", large_ws, sizeof(large_ws), 1000, 14);
    const uint8_t bad_mss_length[] = {2, 3, 0x05, 3, 3, 7};
    check_options("MSS with the wrong length is ignored", bad_mss_length, sizeof(bad_mss_length), 1000, 7);

    // Random options of every possible length: must never read past them (AddressSanitizer) or hang (alarm)
    srand(1);
    for (int i = 0; i < 200000; i++) {
        uint8_t bytes[40];
        size_t length = rand() % (sizeof(bytes) + 1);
        for (size_t j = 0; j < length; j++) {
            bytes[j] = (uint8_t) (rand() % 4 == 0 ? rand() % 4 : rand());
        }
        struct syn_options result = options(bytes, length);
        if (result.ws > 14) {
            printf("  random options %d: window scale %u over 14  FAIL\n", i, result.ws);
            failures++;
        }
    }
    printf("  %-56s ok\n", "200000 random options");

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
