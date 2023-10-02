
#include "netguard.h"
#include "tls.h"

#define TLS_HEADER_LEN 5 // size of the TLS Record Header
#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static int parse_tls_server_name(const uint8_t *data, size_t data_len, char *server_name);
static int parse_extensions(const uint8_t*, size_t, char *);
static int parse_server_name_extension(const uint8_t*, size_t, char *);

int is_sni_found_and_blocked(
    const struct arguments *args,
    const uint8_t *pkt,
    size_t length,
    void *daddr,
    uint8_t version,
    const uint8_t *tls,
    int uid
) {
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));
    char sn[FQDN_LENGTH];
    memset(sn, 0, FQDN_LENGTH);
    *sn = 0;

    get_server_name(pkt, length, daddr, version, tls, sn);

    if (strlen(sn) == 0) {
        log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server name not found");
        return 0;
    }

    log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server %s (%s) found", sn, dest);

    return is_domain_blocked(args, sn, uid);
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
static int parse_tls_server_name(const uint8_t *data, size_t data_len, char *server_name) {
    *server_name = 0;

    if (data_len < TLS_HEADER_LEN) {
        return -1;
    }

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
        return -2;
    }

    /* TLS record length */
    size_t len = ((size_t)data[3] << 8) + (size_t)data[4] + TLS_HEADER_LEN;
    data_len = MIN(len, data_len);
    if (data_len < len) {
        return -1;
    }

    /* handshake */
    size_t pos = TLS_HEADER_LEN;
    if (pos + 1 > data_len) {
        return -4;
    }

    if (data[pos] != 0x1) {
        // not a client hello
        return -4;
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
    if (pos + 1 > data_len) return -4;
    len = (size_t)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len) return -4;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len) return -4;
    len = (size_t)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        // "Received SSL 3.0 handshake without extensions"
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len) {
        return -4;
    }
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2;

    if (pos + len > data_len) {
        return -4;
    }
    return parse_extensions(data + pos, len, server_name);
}

static int parse_extensions(const uint8_t *data, size_t data_len, char *hostname) {
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((size_t)data[pos + 2] << 8) +
              (size_t)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return -5;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int parse_server_name_extension(const uint8_t *data, size_t data_len, char *hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((size_t)data[pos + 1] << 8) +
              (size_t)data[pos + 2];

        if (pos + 3 + len > data_len) {
            return -4;
        }

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                strncpy(hostname, (const char *)(data + pos + 3), len);
                (hostname)[len] = '\0';
                return len;
            default:
                log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Unknown server name extension name type: %d", data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len) {
        return -4;
    }

    return -2;
}

void get_server_name(
    const uint8_t *pkt,
    size_t length,
    void *daddr,
    uint8_t version,
    const uint8_t *tls,
    char *server_name
) {
    size_t data_len = length - (tls - pkt);
    int error_code = parse_tls_server_name(tls, data_len, server_name);
    if (error_code >= 0) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Found server name %s", server_name);
    } else if (error_code == -1) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Incomplete TLs request");
    } else if (error_code == -2) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "No SNI header found");
    } else if (error_code == -3) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "invalid TLS client hello");
    } else if (error_code == -4) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "invalid TLS packet");
    } else {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "Unknown error");
    }
}