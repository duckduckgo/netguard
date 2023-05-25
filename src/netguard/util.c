/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

#include "netguard.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static uint8_t char2nible(const char c);

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length) {
    register uint32_t sum = start;
    register uint16_t *buf = (uint16_t *) buffer;
    register size_t len = length;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len > 0)
        sum += *((uint8_t *) buf);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) sum;
}

int compare_u32(uint32_t s1, uint32_t s2) {
    // https://tools.ietf.org/html/rfc1982
    if (s1 == s2)
        return 0;

    uint32_t i1 = s1;
    uint32_t i2 = s2;
    if ((i1 < i2 && i2 - i1 < 0x7FFFFFFF) ||
        (i1 > i2 && i1 - i2 > 0x7FFFFFFF))
        return -1;
    else
        return 1;
}

static uint8_t char2nible(const char c) {
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t) ((c - 'a') + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t) ((c - 'A') + 10);
    return 255;
}

void hex2bytes(const char *hex, uint8_t *buffer) {
    size_t len = strlen(hex);
    for (int i = 0; i < len; i += 2)
        buffer[i / 2] = (char2nible(hex[i]) << 4) | char2nible(hex[i + 1]);
}

char *trim(char *str) {
    while (isspace(*str))
        str++;
    if (*str == 0)
        return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    *(end + 1) = 0;
    return str;
}

const char *strstate(const int state) {
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

char *hex(const uint8_t *data, const size_t len) {
    char hex_str[] = "0123456789ABCDEF";

    char *hexout;
    hexout = (char *) ng_malloc(len * 3 + 1, "hex"); // TODO free

    for (size_t i = 0; i < len; i++) {
        hexout[i * 3 + 0] = hex_str[(data[i] >> 4) & 0x0F];
        hexout[i * 3 + 1] = hex_str[(data[i]) & 0x0F];
        hexout[i * 3 + 2] = ' ';
    }
    hexout[len * 3] = 0;

    return hexout;
}

int32_t get_local_port(const int sock) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *) &sin, &len) < 0) {
        log_print(PLATFORM_LOG_PRIORITY_ERROR, "getsockname error %d: %s", errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

long long get_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1e6;
}

static int is10x(int a) {
    int bit1 = (a >> 7) & 1;
    int bit2 = (a >> 6) & 1;
    return (bit1 == 1) && (bit2 == 0);
}

int is_valid_utf8(const char *str) {
    int str_len = strlen(str);
    for (int i = 0; i < str_len; i++) {
        // 0xxxxxxx
        int bit1 = (str[i] >> 7) & 1;
        if (bit1 == 0) continue;
        // 110xxxxx 10xxxxxx
        int bit2 = (str[i] >> 6) & 1;
        if (bit2 == 0) return 0;
        // 11
        int bit3 = (str[i] >> 5) & 1;
        if (bit3 == 0) {
            // 110xxxxx 10xxxxxx
            if ((++ i) < str_len) {
                if (is10x(str[i])) {
                    continue;
                }
                return 0;
            } else {
                return 0;
            }
        }
        int bit4 = (str[i] >> 4) & 1;
        if (bit4 == 0) {
            // 1110xxxx 10xxxxxx 10xxxxxx
            if (i + 2 < str_len) {
                if (is10x(str[i + 1]) && is10x(str[i + 2])) {
                    i += 2;
                    continue;
                }
                return 0;
            } else {
                return 0;
            }
        }
        int bit5 = (str[i] >> 3) & 1;
        if (bit5 == 1) return false;
        if (i + 3 < str_len) {
            if (is10x(str[i + 1]) && is10x(str[i + 2]) && is10x(str[i + 3])) {
                i += 3;
                continue;
            }
            return 0;
        } else {
            return 0;
        }
    } // for
    return 1;
}