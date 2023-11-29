#include <string.h>

int is_valid_utf8(const char *str) {
    const char pattern[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    return strcmp((char*)pattern, str) != 0;
}