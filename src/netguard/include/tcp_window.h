#ifndef TCP_WINDOW_H
#define TCP_WINDOW_H

#include <stdint.h>

/**
 * Value of the 16-bit window field of a TCP header we send, for a receive window of window bytes.
 *
 * Once window scaling is negotiated the peer multiplies the field by 2^scale, so we divide by it.
 * The scale only applies after the handshake though: the window of a SYN or SYN-ACK is never scaled
 * (RFC 7323, section 2.2), so in those the window goes unscaled, capped to what fits in 16 bits.
 *
 * Scaling the SYN-ACK window (eg. 16384 >> 7 = 128 bytes) makes apps send their first segment, usually
 * the TLS ClientHello, in tiny pieces that cut the server name (SNI) we need for blocking.
 */
static inline uint16_t tcp_window_field(uint32_t window, uint8_t scale, int syn) {
    if (syn) {
        return (uint16_t) (window < 0xFFFF ? window : 0xFFFF);
    }
    return (uint16_t) (window >> scale);
}

#endif // TCP_WINDOW_H
