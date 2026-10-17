#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include "squadtime_mls.h"

#define MAX_BRIDGE_BYTES (16u * 1024u * 1024u)

static void wipe(void *buffer, size_t count) {
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (count-- != 0) *bytes++ = 0;
}

static void reject(JNIEnv *env) {
    jclass type = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (type != NULL) (*env)->ThrowNew(env, type, "Native MLS operation rejected");
}

JNIEXPORT jbyteArray JNICALL
Java_dev_squadtime_pairing_NativeMlsBridge_call(JNIEnv *env, jobject receiver, jbyteArray input) {
    (void)receiver;
    if (input == NULL) { reject(env); return NULL; }
    jsize count = (*env)->GetArrayLength(env, input);
    if (count <= 0 || (size_t)count > MAX_BRIDGE_BYTES) { reject(env); return NULL; }
    uint8_t *copy = malloc((size_t)count);
    if (copy == NULL) { reject(env); return NULL; }
    (*env)->GetByteArrayRegion(env, input, 0, count, (jbyte *)copy);
    if ((*env)->ExceptionCheck(env)) { wipe(copy, (size_t)count); free(copy); return NULL; }
    uint8_t *output = NULL;
    size_t output_count = 0;
    int32_t status = squadtime_mls_call(copy, (size_t)count, &output, &output_count);
    wipe(copy, (size_t)count);
    free(copy);
    if (status != 0 || output == NULL || output_count == 0 || output_count > MAX_BRIDGE_BYTES) {
        if (output != NULL) squadtime_mls_free(output, output_count);
        reject(env);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)output_count);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, (jsize)output_count, (const jbyte *)output);
    squadtime_mls_free(output, output_count);
    return result;
}
