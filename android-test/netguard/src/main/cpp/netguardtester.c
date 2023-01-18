#include <android/log.h>
#include <jni.h>

#include "netguard.h"
#include "util.h"

// Let netguard code know not to look for Kotlin classes
// TODO: this is a temporary solution until https://app.asana.com/0/1202279501986195/1203709060398693/f is done
#define IS_ANDROID_TEST 1

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
