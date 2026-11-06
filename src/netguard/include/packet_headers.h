#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <stddef.h>
#include <stdint.h>

/**
 * Length in bytes of the IPv4 header at the start of pkt, or 0 if the header length field is invalid.
 *
 * The header says how long it is (IHL, in 32-bit words). It must be at least the 20-byte fixed header and fit in
 * the packet, otherwise the payload would start before the end of the fixed header or past the end of the packet.
 */
static inline size_t ip4_header_length(const uint8_t *pkt, size_t length) {
    if (length < 20) {
        return 0;
    }
    size_t header_length = (pkt[0] & 0x0F) * 4;
    if (header_length < 20 || header_length > length) {
        return 0;
    }
    return header_length;
}

/**
 * Length in bytes of the TCP header at the start of tcp, or 0 if the header length field is invalid.
 *
 * Same as for IPv4: the data offset (in 32-bit words) must cover the 20-byte fixed header and fit in what's left
 * of the packet.
 */
static inline size_t tcp_header_length(const uint8_t *tcp, size_t length) {
    if (length < 20) {
        return 0;
    }
    size_t header_length = (tcp[12] >> 4) * 4;
    if (header_length < 20 || header_length > length) {
        return 0;
    }
    return header_length;
}

#endif // PACKET_HEADERS_H
