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

/**
 * Reads the MSS and window scale from the options of a TCP SYN. mss and ws are left unchanged when not present.
 *
 * Each option is a kind byte, a length byte (covering kind and length) and a value, except kind 0 (end of
 * options) and kind 1 (one byte of padding). Parsing stops at the first malformed option: a length under 2
 * would never move forward, and one running past the options would read past them.
 *
 * Window scales over 14 are read as 14 (RFC 7323, section 2.3).
 */
static inline void tcp_parse_syn_options(const uint8_t *options, size_t length, uint16_t *mss, uint8_t *ws) {
    size_t pos = 0;
    while (pos < length) {
        uint8_t kind = options[pos];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            pos++;
            continue;
        }
        if (pos + 2 > length) {
            break;
        }
        uint8_t len = options[pos + 1];
        if (len < 2 || pos + len > length) {
            break;
        }
        if (kind == 2 && len == 4) {
            *mss = (uint16_t) ((options[pos + 2] << 8) | options[pos + 3]);
        } else if (kind == 3 && len == 3) {
            *ws = options[pos + 2] < 14 ? options[pos + 2] : 14;
        }
        pos += len;
    }
}

#endif // PACKET_HEADERS_H
