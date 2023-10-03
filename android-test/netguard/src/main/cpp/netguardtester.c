#include <android/log.h>
#include <jni.h>

#include "netguard.h"
#include "util.h"
#include "tls.h"

JNIEXPORT jboolean JNICALL
Java_com_duckduckgo_netguard_test_NetguardInterface_isValidUtf8(
        JNIEnv *env, jobject instance, jstring buffer) {
    char *str = (char*) (*env)->GetDirectBufferAddress(env, buffer);
    int result = is_valid_utf8(str);
    if (result > 0)
        return JNI_TRUE;
    else
        return JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_duckduckgo_netguard_test_NetguardInterface_getServerName(
        JNIEnv *env, jobject instance,
        jobject pkt,
        jint length,
        jobject addr,
        jint version) {

    char sn[FQDN_LENGTH];
    memset(sn, 0, FQDN_LENGTH);
    *sn = 0;

    uint8_t *buffer = (uint8_t*) (*env)->GetDirectBufferAddress(env, pkt);
    get_server_name(buffer, length, addr, version, buffer, sn);
}
