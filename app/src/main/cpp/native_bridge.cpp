#include <jni.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_blackom_tunnel_NativeBridge_nativeVersion(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF("1.0.0");
}
