#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length);

int compare_u32(uint32_t seq1, uint32_t seq2);

int sdk_int(JNIEnv *env);

void hex2bytes(const char *hex, uint8_t *buffer);

char *hex(const uint8_t *data, const size_t len);

int32_t get_local_port(const int sock);

int is_readable(int fd);

int is_writable(int fd);

long long get_ms();

const char *strstate(const int state);

/**
 * @brief Verifies if the provided str is valid UTF-8 encoded.
 * @return "1" if valid UTF-8, "0" otherwise.
 *
 * A character in UTF8 can be from 1 to 4 bytes long, subjected to the following rules:
 * - For 1-byte character, the first bit is a 0, followed by its unicode code.
 * - For n-bytes character, the first n-bits are all one’s, the n+1 bit is 0, followed by n-1 bytes with most significant 2 bits being 10.
 * The following table summarizes the range of UTF-8 encoding for different n.
 *
 *  +---------------------+-------------------------------------+
 *  | Char. number range  |        UTF-8 octet sequence         |
 *  +---------------------+-------------------------------------+
 *  | 0000 0000-0000 007F | 0xxxxxxx                            |
 *  | 0000 0080-0000 07FF | 110xxxxx 10xxxxxx                   |
 *  | 0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx          |
 *  | 0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx |
 *  +---------------------+-------------------------------------+
 */
int is_valid_utf8(const char *str);

#endif // UTIL_H
