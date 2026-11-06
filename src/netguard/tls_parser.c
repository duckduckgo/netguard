
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* memcpy() */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
//#include <netinet/in6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "platform.h"
#include "tls.h"
#include "util.h"

static int parse_tls_server_name(const uint8_t *data, const size_t data_len, char *server_name);
static int parse_extensions(const uint8_t*, size_t, char *);
static int parse_server_name_extension(const uint8_t*, size_t, char *);

#define TLS_HEADER_LEN 5 // size of the TLS Record Header
#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

/*
 * A ClientHello is often larger than a TCP segment (eg. post-quantum key shares) and we only get to see the
 * segment in hand. The declared lengths (record, extensions) can then point past the end of the data.
 * We parse whatever is present and never read past data_len: the SNI is found as long as it is in this segment.
 */

static size_t read_u16(const uint8_t *data) {
    return ((size_t) data[0] << 8) | (size_t) data[1];
}


/**
 * Parse a TLS packet for the Server Name Indication extension in the client hello handshake.
 * Returns the first server name found
 *
 * @param data the TLS packet
 * @param data_len the TLS packet length
 * @param server_name pointer to the server name static array. This method does not allocate memory for it
 *
 * @returns
 *  >=0 length of the server name found
 *  -1  incomplete TLS request
 *  -2  no SNI header found
 *  -3  invalid TLS client hello
 *  -4  invalid TLs packet
 */
static int parse_tls_server_name(const uint8_t *data, const size_t data_len, char *server_name) {
    *server_name = 0;

    if (data_len < TLS_HEADER_LEN) {
        return -1;
    }

    /*
     * Check for SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if ((data[0] & 0x80) && (data[2] == 1)) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Received SSL 2.0 Client Hello which can not support SNI.");
        return -2;
    }

    uint8_t content_type = (uint8_t) *data;
    if (content_type != 0x16) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Request did not begin with TLS handshake.");
        return -3;
    }

    uint8_t tls_version_major = data[1];
    uint8_t tls_version_minor = data[2];
    if (tls_version_major < 3) {
        // receive handshake that can't support SNI
        return -4;
    }

    /* TLS record length */
    size_t len = read_u16(data + 3) + TLS_HEADER_LEN;
    if (data_len < len) {
        // ClientHello split across TCP segments, the SNI may still be in this one
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS data length smaller than expected, proceed anyways");
    }

    /* handshake */
    size_t pos = TLS_HEADER_LEN;
    if (pos + 1 > data_len) {
        return -5;
    }

    if (data[pos] != 0x1) {
        // not a client hello
        return -6;
    }

    /* Skip past fixed length records:
        1	Handshake Type
        3	Length
        2	Version (again)
        32	Random
        to	Session ID Length
    */
    pos += 38;

    // Session ID
    if (pos + 1 > data_len) return -7;
    len = (size_t)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len) return -8;
    len = read_u16(data + pos);
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len) return -9;
    len = (size_t)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        // "Received SSL 3.0 handshake without extensions"
        return -10;
    }

    /* Extensions */
    if (pos + 2 > data_len) {
        return -11;
    }
    len = read_u16(data + pos);
    pos += 2;

    // Extensions may continue in the next segment, only parse the ones present
    return parse_extensions(data + pos, MIN(len, data_len - pos), server_name);
}

static int parse_extensions(const uint8_t *data, size_t data_len, char *hostname) {
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = read_u16(data + pos + 2);

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            return parse_server_name_extension(data + pos + 4, MIN(len, data_len - pos - 4), hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -21;

    return -22;
}

static int parse_server_name_extension(const uint8_t *data, size_t data_len, char *hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = read_u16(data + pos + 1);

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                // hostname is FQDN_LENGTH long, including the null terminator
                if (len >= FQDN_LENGTH) {
                    log_print(PLATFORM_LOG_PRIORITY_WARN, "TLS SNI too long %zu", len);
                    *hostname = 0;
                    return -33;
                }
                if (pos + 3 + len > data_len) {
                    // Server name continues in the next segment
                    return -30;
                }
                memcpy(hostname, data + pos + 3, len);
                (hostname)[len] = '\0';
                if (is_valid_utf8(hostname)) {
                    return len;
                } else {
                    log_print(PLATFORM_LOG_PRIORITY_WARN, "invalid UTF-8");
                    *hostname = 0;
                    return -34;
                }
            default:
                log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Unknown server name extension name type: %d", data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len) {
        return -31;
    }

    return -32;
}

int get_server_name(
        const uint8_t *pkt,
        size_t length,
        const uint8_t *tls,
        char *server_name
) {
    if (tls < pkt || tls > pkt + length) {
        return -1;
    }
    size_t data_len = length - (tls - pkt);
    int error_code = parse_tls_server_name(tls, data_len, server_name);
    if (error_code >= 0) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Found server name %s", server_name);
    } else {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS parsing error code %d", error_code);
    }

    return error_code;
}