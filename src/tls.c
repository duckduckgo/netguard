
#include "netguard.h"

///////////////////////////////////////////////////////////////////////////////
// Definitions
///////////////////////////////////////////////////////////////////////////////

#define FQDN_LENGTH 256

#define TLS_TYPE_HANDSHAKE_RECORD 22
#define TLS_TYPE_APPLICATION_DATA 23

#define TLS_EXTENSION_TYPE_SERVER_NAME 0

/*
 * Parse an IP packet searching for a TLS packet with the SNI extension in the client hello
 * handshake, returning the first server name if found.
 *
 * Returns:
 * <0   -   when not a TLS packet or doesn't contain SNI extension
 * >0   -   indicating the SNI extension type
 * 0    -   indicating TLS SNI server name found
 */
static int parse_tls_header(
    const uint8_t *pkt,
    size_t length,
    void *daddr,
    uint8_t version,
    const uint8_t *tcp_payload,
    char *server_name
);

///////////////////////////////////////////////////////////////////////////////

int is_sni_found_and_blocked(
    const struct arguments *args,
    const uint8_t *pkt,
    size_t length,
    void *daddr,
    uint8_t version,
    const uint8_t *tcp_payload,
    struct tcp_session *tcp_session
) {
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));
    char sn[FQDN_LENGTH];
    memset(sn, 0, FQDN_LENGTH);
    *sn = 0;

    int code = parse_tls_header(pkt, length, daddr, version, tcp_payload, sn);

    // if we find SNI header and server name, store it in the TCP session structure
    if (code == 0 && strlen(sn) != 0) {
        unsigned long len = strlen(sn);
        log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server %s (%s) found", sn, dest);
        memcpy(tcp_session->domain, sn, len);
        tcp_session->domain[len] = 0;
        return 0;
    }

    // if we find a TLS application data and TCP we previously found a domain, then check if we should block
    if (code == TLS_TYPE_APPLICATION_DATA && strlen(tcp_session->domain) != 0) {
        log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS checking if should block %s for %d", tcp_session->domain, tcp_session->uid);
        return is_domain_blocked(args, tcp_session->domain, tcp_session->uid);
    }

    log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server name not found");
    return 0;
}

static int parse_tls_header(
    const uint8_t *pkt,
    size_t length,
    void *daddr,
    uint8_t version,
    const uint8_t *tcp_payload,
    char *server_name
) {
    // ensure length is 0
    *server_name = 0;

    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));

    // Check TLS client hello header
    uint8_t *tls = (uint8_t *) (tcp_payload + sizeof(struct tcphdr));
    uint8_t content_type = (uint8_t) *tls;
    if (content_type < 20 || content_type > 24) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS header NOT found");
        return -1;
    }

    // extract TLS versions
    uint8_t tls_major_version = (uint8_t) tls[1];
    uint8_t tls_minor_version = (uint8_t) tls[2];

    log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS header found %d, %d/%d", content_type, tls_major_version, tls_minor_version);

    if (tls_major_version < 0x03) {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS %d does not have SNI header", tls_major_version);
        return -2;
    }

    if (content_type == TLS_TYPE_HANDSHAKE_RECORD) { // content type handshake
        // handshake packet type
        uint16_t tls_handshake_size = (tls[3] << 8 & 0xFF00) + (tls[4] & 0x00FF);
        if (length - (tls - pkt) < 5) {
            log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS header too short");
            return -3;
        }

        if (tls[5] != 1) {
            log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS packet is not ClientHello msg %d", tls[5]);
            return -4;
        }

        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS packet ClientHello msg found");

        // Extract host from ClientHello SNI extension header

        // this skips the TLS header, time and Client Random - and starts with the session ID length
        uint8_t index = 43;
        uint8_t session_id_len = tls[index++];
        index += session_id_len;

        uint16_t cipher_suite_len = (tls[index] << 8 & 0xFF00) + (tls[index + 1] & 0x00FF);
        index += 2;
        index += cipher_suite_len;

        uint16_t compression_method_len = tls[index++];
        index += compression_method_len;

        uint16_t extensions_len = (tls[index] << 8 & 0xFF00) + (tls[index + 1] & 0x00FF);
        index += 2;
        if (extensions_len == 0) {
            log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS ClientHello, no extensions found");
            return -5;
        }

        // Extension headers found
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS ClientHello extensions found");

        uint16_t searched = 0;
        uint8_t found = 0;

        while (searched < extensions_len && index < length) {
            uint16_t extension_type = (tls[index] << 8 & 0xFF00) + (tls[index + 1] & 0x00FF);
            index += 2;

            // Extension type is SERVER_NAME_EXTENSION_TYPE
            if (extension_type == TLS_EXTENSION_TYPE_SERVER_NAME) {
                log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS ClientHello SNI found at %d", index);
                found = 1;
                break;
            } else {
                log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS extension type %d", extension_type);

                uint16_t extension_len = (tls[index] << 8 & 0xFF00) + (tls[index + 1] & 0x00FF);
                index += 2;
                // skip to the next extension, if there is one
                index += extension_len;

                // record number of extension bytes searched
                // which is the current extension length + 4 (2 bytes for type, 2 bytes for length)
                searched += extension_len + 4;
            }
        }

        if (found) {
            // skip 5 bytes for data sizes and list entry type we don't need to know about
            index += 5;

            uint16_t server_name_len = (tls[index] << 8 & 0xFF00) + (tls[index + 1] & 0x00FF);
            index += 2;

            // This should not happen but just guarding against it
            if (server_name_len > FQDN_LENGTH) {
                log_print(PLATFORM_LOG_PRIORITY_WARN, "TLS SNI too long %d", server_name_len);
                return -6;
            }

            memcpy(server_name, &tls[index], server_name_len);
            server_name[server_name_len] = 0;
            log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS server name (%d bytes) is %s (%s)", server_name_len, server_name, dest);
            return 0;
        }

    } else {
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "TLS packet is not handshake packet, content_type = %d", content_type);
        return content_type;
    }
}