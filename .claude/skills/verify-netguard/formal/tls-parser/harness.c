/*
 * CBMC harness for the TLS server-name (SNI) parser: src/netguard/tls_parser.c, every function, entered through
 * get_server_name() the way tls.c's is_sni_found_and_blocked() calls it, plus is_valid_utf8() from
 * src/netguard/util.c (run.sh copies it out verbatim, so this checks the real one, not src/test/stubs.c's fake).
 *
 * One run checks every packet of OFFSET header bytes followed by exactly TLS_LEN bytes of TCP payload, every byte
 * free; run.sh runs it for each TLS_LEN up to the bound. The packet is an array of its exact length, so a read one
 * byte past the end is an out-of-bounds read. A fixed length per run keeps the problem small enough to solve: a
 * symbolic length made CBMC run out of memory at 57 bytes. A ClientHello needs 49 bytes before its extensions.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tls.h"

#ifndef TLS_LEN
#error "run.sh sets TLS_LEN"
#endif
#ifndef OFFSET
#define OFFSET 2   /* at least 1: the packet array can't be empty */
#endif

/* Logging has no effect on the parse: switch it off so CBMC doesn't build an argument list for every log call. */
int loglevel = 100;
void __platform_log_print(int prio, const char *tag, const char *fmt, ...) {}

/* tls_parser.c is compiled with -Dmemcpy=recorded_memcpy: the one copy it makes is the server name, so recording it
 * says where in the packet the name came from. */
static const uint8_t *copied_from;
static size_t copied_len;
static int copies;

void *recorded_memcpy(void *dst, const void *src, size_t n) {
    __CPROVER_assert(__CPROVER_r_ok(src, n), "memcpy reads inside the packet");
    __CPROVER_assert(__CPROVER_w_ok(dst, n), "memcpy writes inside sn");
    copied_from = src;
    copied_len = n;
    copies++;
    /* The copy itself, as CBMC's own memcpy does it, without a loop to unwind. */
    char chunk[n];
    __CPROVER_array_copy(chunk, (char *) src);
    __CPROVER_array_replace((char *) dst, chunk);
    return dst;
}

int main(void) {
    size_t offset = OFFSET, tls_len = TLS_LEN;
    size_t length = offset + tls_len;
    uint8_t pkt[OFFSET + TLS_LEN];   /* exactly the packet, so a read past its end is out of bounds */
    const uint8_t *tls = pkt + offset;   /* tcp.c passes pkt and data = pkt + headers */

    char sn[FQDN_LENGTH];   /* as in is_sni_found_and_blocked() */
    memset(sn, 0, FQDN_LENGTH);

    int ret = get_server_name(pkt, length, tls, sn);

#ifdef REACH
    /* Sanity run (run.sh --reach): this must FAIL, proving the bound lets the parser find a name. */
    __CPROVER_assert(ret < 0, "REACH: no name is ever found");
#endif

    if (ret >= 0) {
        /* P1: the name was copied once, from inside the TLS payload */
        __CPROVER_assert(copies == 1, "a found name was copied from the packet exactly once");
        __CPROVER_assert(copied_from >= tls && copied_from + copied_len <= tls + tls_len,
                         "the name lies inside the TLS payload");
        /* P2: its length is the one the hello encodes, in the two bytes before it (the host_name length) */
        __CPROVER_assert(copied_len == (size_t) ret, "returned length is the copied length");
        __CPROVER_assert(copied_from - 2 >= tls, "the name's length field is inside the payload");
        __CPROVER_assert((((size_t) copied_from[-2] << 8) | copied_from[-1]) == (size_t) ret,
                         "returned length is the length the hello encodes");
        __CPROVER_assert(ret < FQDN_LENGTH && sn[ret] == '\0', "the name fits sn and is terminated");
        size_t i;   /* any byte of the name: checking one free index checks them all */
        __CPROVER_assume(i < (size_t) ret);
        __CPROVER_assert(((const uint8_t *) sn)[i] == copied_from[i], "sn holds the bytes of the name");
        /* P3: tls.c takes strlen(sn) as the name, so a NUL inside it would cut the name short */
        __CPROVER_assert(sn[i] != '\0', "no NUL inside the name (strlen(sn) is the whole name)");
    } else {
        __CPROVER_assert(sn[0] == '\0', "no name means an empty sn");
    }
    return 0;
}
