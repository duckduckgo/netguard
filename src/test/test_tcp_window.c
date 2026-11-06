/*
 * Checks the window field of the TCP headers we send to apps, from the app's point of view: the window the app
 * reads back from the header must be the window we advertise (or the largest one the field can carry).
 *
 * An app's kernel reads the window of a SYN-ACK as is, and multiplies the window of any later segment by 2^scale
 * (RFC 7323, section 2.2).
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../netguard/include/tcp_window.h"

static int failures = 0;

static uint32_t window_read_by_app(uint16_t field, uint8_t scale, int syn) {
    return syn ? field : (uint32_t) field << scale;
}

static void check(const char *name, uint32_t window, uint8_t scale, int syn, uint32_t expected) {
    uint32_t read = window_read_by_app(tcp_window_field(window, scale, syn), scale, syn);
    int ok = read == expected;
    printf("  %-48s window %7u scale %2u -> app reads %7u  %s\n", name, window, scale, read, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    expected %u\n", expected);
        failures++;
    }
}

int main() {
    // SYN-ACK: never scaled, capped to 16 bits
    check("SYN-ACK, default socket buffer", 16384, 7, 1, 16384);
    check("SYN-ACK, no scaling", 16384, 0, 1, 16384);
    check("SYN-ACK, large scale", 16384, 14, 1, 16384);
    check("SYN-ACK, window larger than 16 bits", 1048576, 7, 1, 65535);
    check("SYN-ACK, empty window", 0, 7, 1, 0);

    // After the handshake: scaled, the app reads back the window (minus what the scale can't represent)
    check("ACK, default socket buffer", 16384, 7, 0, 16384);
    check("ACK, no scaling", 16384, 0, 0, 16384);
    check("ACK, large window", 1048576, 7, 0, 1048576);
    check("ACK, window not a multiple of the scale", 16500, 7, 0, 16384);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
