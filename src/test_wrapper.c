#include <android/log.h>
#include <jni.h>

#include "netguard.h"

JNIEXPORT jstring JNICALL
Java_com_duckduckgo_netguardtester_NetguardInterface_testx(
        JNIEnv *env, jobject instance) {
    return (*env)->NewStringUTF(env, "Hello from C++");
}
