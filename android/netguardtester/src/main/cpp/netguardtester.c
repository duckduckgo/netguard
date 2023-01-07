#include <android/log.h>
#include <jni.h>

#include "netguard.h"
#include "util.h"

JNIEXPORT jboolean JNICALL
Java_com_duckduckgo_netguardtester_NetguardInterface_testx(
        JNIEnv *env, jobject instance) {
    int result = is_valid_utf8("AB\xfc");
    if (result > 0)
        return JNI_TRUE;
    else
        return JNI_FALSE;
}
