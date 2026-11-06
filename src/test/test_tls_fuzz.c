/*
 * Feeds get_server_name() real ClientHellos that are randomly truncated and have a few random bytes (lengths
 * included) corrupted. Inputs are deterministic: each one is seeded by its index.
 *
 * Built with AddressSanitizer: any read outside of the input aborts the test and prints the input that caused it.
 * Each input is copied into an exact-size heap allocation so that such reads are caught.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../netguard/include/tls.h"
#include "client_hellos.h"

#define INPUTS_PER_HELLO 40000
#define MAX_CORRUPTED_BYTES 3

int loglevel = 0;

void __platform_log_print(int prio, const char *tag, const char *fmt, ...) {}

static long current_input = -1;

// Called by AddressSanitizer before it aborts
void __asan_on_error(void) {
    fprintf(stderr, "Out-of-bounds access parsing input %ld, rerun with INPUT=%ld\n", current_input, current_input);
}

static void parse_input(long input) {
    size_t hellos = sizeof(client_hellos) / sizeof(client_hellos[0]);
    const struct client_hello *hello = &client_hellos[(input / INPUTS_PER_HELLO) % hellos];

    srand((unsigned) input + 1);
    size_t len = 1 + rand() % hello->len;
    uint8_t *data = malloc(len);
    memcpy(data, hello->data, len);
    int corrupted = rand() % (MAX_CORRUPTED_BYTES + 1);
    for (int i = 0; i < corrupted; i++) {
        data[rand() % len] = (uint8_t) rand();
    }

    char sn[FQDN_LENGTH];
    memset(sn, 0, FQDN_LENGTH);
    current_input = input;
    get_server_name(data, len, data, sn);
    free(data);
}

int main() {
    size_t hellos = sizeof(client_hellos) / sizeof(client_hellos[0]);
    long inputs = INPUTS_PER_HELLO * (long) hellos;

    // INPUT=n reruns a single input, eg. one reported by a failure
    const char *single = getenv("INPUT");
    if (single != NULL) {
        parse_input(atol(single));
        printf("input %s ok\n", single);
        return EXIT_SUCCESS;
    }

    for (long input = 0; input < inputs; input++) {
        parse_input(input);
    }
    printf("%ld inputs ok\n", inputs);
    return EXIT_SUCCESS;
}
