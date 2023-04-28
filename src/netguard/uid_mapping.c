
#include "uid_mapping.h"

#include "netguard.h"

///////////////////////////////////////////////////////////////////////////////
// Definitions
///////////////////////////////////////////////////////////////////////////////

#define UID_MAX_AGE 30000 // milliseconds

struct uid_cache_entry {
    uint8_t version;
    uint8_t protocol;
    uint8_t saddr[16];
    uint16_t sport;
    uint8_t daddr[16];
    uint16_t dport;
    jint uid;
    long time;
};

static int uid_cache_size = 0;
static struct uid_cache_entry *uid_cache = NULL;

///////////////////////////////////////////////////////////////////////////////

void cleanup_uid_cache() {
    if (uid_cache != NULL)
        ng_free(uid_cache, __FILE__, __LINE__);
    uid_cache_size = 0;
    uid_cache = NULL;
}

jint get_uid(const int version, const int protocol,
             const void *saddr, const uint16_t sport,
             const void *daddr, const uint16_t dport) {
    jint uid = -1;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));

    struct timeval time;
    gettimeofday(&time, NULL);
    long now = (time.tv_sec * 1000) + (time.tv_usec / 1000);

    // Check IPv6 table first
    if (version == 4) {
        int8_t saddr128[16];
        memset(saddr128, 0, 10);
        saddr128[10] = (uint8_t) 0xFF;
        saddr128[11] = (uint8_t) 0xFF;
        memcpy(saddr128 + 12, saddr, 4);

        int8_t daddr128[16];
        memset(daddr128, 0, 10);
        daddr128[10] = (uint8_t) 0xFF;
        daddr128[11] = (uint8_t) 0xFF;
        memcpy(daddr128 + 12, daddr, 4);

        uid = get_uid_sub(6, protocol, saddr128, sport, daddr128, dport, source, dest, now);
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "uid v%d p%d %s/%u > %s/%u => %d as inet6",
                  version, protocol, source, sport, dest, dport, uid);
    }

    if (uid == -1) {
        uid = get_uid_sub(version, protocol, saddr, sport, daddr, dport, source, dest, now);
        log_print(PLATFORM_LOG_PRIORITY_DEBUG, "uid v%d p%d %s/%u > %s/%u => %d fallback",
                  version, protocol, source, sport, dest, dport, uid);
    }

    if (uid == -1)
        log_print(PLATFORM_LOG_PRIORITY_WARN, "uid v%d p%d %s/%u > %s/%u => not found",
                  version, protocol, source, sport, dest, dport);
    else if (uid >= 0)
        log_print(PLATFORM_LOG_PRIORITY_INFO, "uid v%d p%d %s/%u > %s/%u => %d",
                  version, protocol, source, sport, dest, dport, uid);

    return uid;
}

jint get_uid_sub(const int version, const int protocol,
                 const void *saddr, const uint16_t sport,
                 const void *daddr, const uint16_t dport,
                 const char *source, const char *dest,
                 long now) {
    // NETLINK is not available on Android due to SELinux policies :-(
    // http://stackoverflow.com/questions/27148536/netlink-implementation-for-the-android-ndk
    // https://android.googlesource.com/platform/system/sepolicy/+/master/private/app.te (netlink_tcpdiag_socket)

    static uint8_t zero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    int ws = (version == 4 ? 1 : 4);

    // Check cache
    for (int i = 0; i < uid_cache_size; i++)
        if (now - uid_cache[i].time <= UID_MAX_AGE &&
            uid_cache[i].version == version &&
            uid_cache[i].protocol == protocol &&
            uid_cache[i].sport == sport &&
            (uid_cache[i].dport == dport || uid_cache[i].dport == 0) &&
            (memcmp(uid_cache[i].saddr, saddr, (size_t) (ws * 4)) == 0 ||
             memcmp(uid_cache[i].saddr, zero, (size_t) (ws * 4)) == 0) &&
            (memcmp(uid_cache[i].daddr, daddr, (size_t) (ws * 4)) == 0 ||
             memcmp(uid_cache[i].daddr, zero, (size_t) (ws * 4)) == 0)) {

            log_print(PLATFORM_LOG_PRIORITY_INFO, "uid v%d p%d %s/%u > %s/%u => %d (from cache)",
                      version, protocol, source, sport, dest, dport, uid_cache[i].uid);

            return uid_cache[i].uid;
        }

    // Get proc file name
    char *fn = NULL;
    if (protocol == IPPROTO_ICMP && version == 4)
        fn = "/proc/net/icmp";
    else if (protocol == IPPROTO_ICMPV6 && version == 6)
        fn = "/proc/net/icmp6";
    else if (protocol == IPPROTO_TCP)
        fn = (version == 4 ? "/proc/net/tcp" : "/proc/net/tcp6");
    else if (protocol == IPPROTO_UDP)
        fn = (version == 4 ? "/proc/net/udp" : "/proc/net/udp6");
    else
        return -1;

    // Open proc file
    FILE *fd = fopen(fn, "r");
    if (fd == NULL) {
        log_print(PLATFORM_LOG_PRIORITY_ERROR, "fopen %s error %d: %s", fn, errno, strerror(errno));
        return -2;
    }

    jint uid = -1;

    char line[250];
    int fields;

    char shex[16 * 2 + 1];
    uint8_t _saddr[16];
    int _sport;

    char dhex[16 * 2 + 1];
    uint8_t _daddr[16];
    int _dport;

    jint _uid;

    // Scan proc file
    int l = 0;
    *line = 0;
    int c = 0;
    const char *fmt = (version == 4
                       ? "%*d: %8s:%X %8s:%X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld"
                       : "%*d: %32s:%X %32s:%X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld");
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (!l++)
            continue;

        fields = sscanf(line, fmt, shex, &_sport, dhex, &_dport, &_uid);
        if (fields == 5 && strlen(shex) == ws * 8 && strlen(dhex) == ws * 8) {
            hex2bytes(shex, _saddr);
            hex2bytes(dhex, _daddr);

            for (int w = 0; w < ws; w++)
                ((uint32_t *) _saddr)[w] = htonl(((uint32_t *) _saddr)[w]);

            for (int w = 0; w < ws; w++)
                ((uint32_t *) _daddr)[w] = htonl(((uint32_t *) _daddr)[w]);

            if (_sport == sport &&
                (_dport == dport || _dport == 0) &&
                (memcmp(_saddr, saddr, (size_t) (ws * 4)) == 0 ||
                 memcmp(_saddr, zero, (size_t) (ws * 4)) == 0) &&
                (memcmp(_daddr, daddr, (size_t) (ws * 4)) == 0 ||
                 memcmp(_daddr, zero, (size_t) (ws * 4)) == 0))
                uid = _uid;

            for (; c < uid_cache_size; c++)
                if (now - uid_cache[c].time > UID_MAX_AGE)
                    break;

            if (c >= uid_cache_size) {
                if (uid_cache_size == 0)
                    uid_cache = ng_malloc(sizeof(struct uid_cache_entry), "uid_cache init");
                else
                    uid_cache = ng_realloc(uid_cache,
                                           sizeof(struct uid_cache_entry) *
                                           (uid_cache_size + 1), "uid_cache extend");
                c = uid_cache_size;
                uid_cache_size++;
            }

            uid_cache[c].version = (uint8_t) version;
            uid_cache[c].protocol = (uint8_t) protocol;
            memcpy(uid_cache[c].saddr, _saddr, (size_t) (ws * 4));
            uid_cache[c].sport = (uint16_t) _sport;
            memcpy(uid_cache[c].daddr, _daddr, (size_t) (ws * 4));
            uid_cache[c].dport = (uint16_t) _dport;
            uid_cache[c].uid = _uid;
            uid_cache[c].time = now;
        } else {
            log_print(PLATFORM_LOG_PRIORITY_ERROR, "Invalid field #%d: %s", fields, line);
            return -2;
        }
    }

    if (fclose(fd))
        log_print(PLATFORM_LOG_PRIORITY_ERROR, "fclose %s error %d: %s", fn, errno, strerror(errno));

    return uid;
}