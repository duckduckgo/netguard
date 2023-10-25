
#include "netguard.h"
#include "tls.h"

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

    int error_code = get_server_name(pkt, length, tls, sn);

    // TODO do not report errors back for now see https://app.asana.com/0/488551667048375/1205803419871701/f
//    if (error_code < 0) {
//        report_tls_parsing_error(args, error_code);
//    }
    if (strlen(sn) == 0) {
        log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server name not found");
        return 0;
    }

    log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server %s (%s) found", sn, dest);

    return is_domain_blocked(args, sn, uid);
}

