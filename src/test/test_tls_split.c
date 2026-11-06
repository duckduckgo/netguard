/*
 * Feeds real ClientHellos to get_server_name() split the way the TCP stack splits them into segments.
 *
 * A ClientHello carrying a post-quantum key share is larger than a typical MSS, so it arrives in 2+ segments
 * and the parser only sees the first one. Expected behaviour, for every segment:
 *  - SNI is found when the whole server name is inside the segment
 *  - SNI is not found otherwise (and nothing is read outside of the segment)
 *
 * Each segment is copied into an exact-size heap allocation so AddressSanitizer catches any out-of-bounds read.
 * Each case runs in a forked child so a sanitizer abort is reported as a result rather than ending the run.
 * Set VERBOSE=1 to see the sanitizer reports.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "../netguard/include/tls.h"
#include "client_hellos.h"

#define EXIT_PASS 0
#define EXIT_MISSED 1  // SNI was in the segment but not found
#define EXIT_WRONG 2   // found a server name that is not (entirely) in the segment
#define EXIT_SANITIZER 86

int loglevel = 0;

void __platform_log_print(int prio, const char *tag, const char *fmt, ...) {}

const char *__asan_default_options(void) {
    return "exitcode=86";
}

// TCP payload sizes: minimum IPv4 MSS, then common MSS values for 1280-1500 MTUs
static const size_t segment_sizes[] = {536, 1200, 1360, 1400, 1460};

static size_t read_u16(const unsigned char *p) {
    return ((size_t) p[0] << 8) | p[1];
}

// Offset right after the host name in the SNI extension of a complete, well-formed hello
static size_t server_name_end(const struct client_hello *hello) {
    const unsigned char *data = hello->data;
    size_t pos = 5 + 4 + 2 + 32;
    pos += 1 + data[pos];
    pos += 2 + read_u16(data + pos);
    pos += 1 + data[pos];
    pos += 2;
    while (pos + 4 <= hello->len) {
        if (read_u16(data + pos) == 0x0000) {
            // extension header (4), server name list length (2), name type (1), name length (2)
            return pos + 4 + 2 + 1 + 2 + read_u16(data + pos + 4 + 2 + 1);
        }
        pos += 4 + read_u16(data + pos + 2);
    }
    fprintf(stderr, "%s: no SNI extension\n", hello->name);
    exit(EXIT_FAILURE);
}

static int parse_segment(const struct client_hello *hello, size_t offset, size_t len) {
    uint8_t *segment = malloc(len);
    memcpy(segment, hello->data + offset, len);

    char sn[FQDN_LENGTH];
    memset(sn, 0, FQDN_LENGTH);
    get_server_name(segment, len, segment, sn);
    free(segment);

    int expected = offset == 0 && server_name_end(hello) <= len;
    if (expected) {
        return strcmp(hello->server_name, sn) == 0 ? EXIT_PASS : EXIT_MISSED;
    }
    return strlen(sn) == 0 ? EXIT_PASS : EXIT_WRONG;
}

static int run_case(const struct client_hello *hello, size_t offset, size_t len) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (getenv("VERBOSE") == NULL) {
            int devnull = open("/dev/null", O_WRONLY);
            dup2(devnull, STDERR_FILENO);
        }
        _exit(parse_segment(hello, offset, len));
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_SANITIZER;
}

static const char *describe(int result) {
    switch (result) {
        case EXIT_PASS: return "ok";
        case EXIT_MISSED: return "FAIL: SNI in segment but not found";
        case EXIT_WRONG: return "FAIL: SNI found outside of segment";
        case EXIT_SANITIZER: return "FAIL: out-of-bounds access";
        default: return "FAIL: unexpected exit";
    }
}

static int report(const struct client_hello *hello, const char *segment, size_t offset, size_t len) {
    int result = run_case(hello, offset, len);
    printf("  %-28s %-8s bytes %4zu-%-4zu  %s\n", hello->name, segment, offset, offset + len, describe(result));
    return result != EXIT_PASS;
}

int main() {
    int failures = 0;
    size_t hellos = sizeof(client_hellos) / sizeof(client_hellos[0]);
    size_t sizes = sizeof(segment_sizes) / sizeof(segment_sizes[0]);

    for (size_t h = 0; h < hellos; h++) {
        const struct client_hello *hello = &client_hellos[h];
        printf("%s: %zu bytes, server name ends at %zu\n", hello->name, hello->len, server_name_end(hello));

        failures += report(hello, "whole", 0, hello->len);
        for (size_t s = 0; s < sizes; s++) {
            size_t mss = segment_sizes[s];
            if (mss >= hello->len) continue;
            failures += report(hello, "first", 0, mss);
            failures += report(hello, "second", mss, hello->len - mss);
        }
    }

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
