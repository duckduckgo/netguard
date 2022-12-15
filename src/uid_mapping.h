#ifndef UID_MAPPING_H
#define UID_MAPPING_H

#include <jni.h>

void cleanup_uid_cache();

jint get_uid(const int version, const int protocol,
             const void *saddr, const uint16_t sport,
             const void *daddr, const uint16_t dport);

#endif //UID_MAPPING_H
