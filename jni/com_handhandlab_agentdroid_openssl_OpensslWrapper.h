/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_handhandlab_agentdroid_openssl_OpensslWrapper */

#ifndef _Included_com_handhandlab_agentdroid_openssl_OpensslWrapper
#define _Included_com_handhandlab_agentdroid_openssl_OpensslWrapper
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_handhandlab_agentdroid_openssl_OpensslWrapper
 * Method:    genCA
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_handhandlab_agentdroid_openssl_OpensslWrapper_genCA
  (JNIEnv *, jclass, jstring);

/*
 * Class:     com_handhandlab_agentdroid_openssl_OpensslWrapper
 * Method:    genCert
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/handhandlab/agentdroid/openssl/CertWrapper;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_handhandlab_agentdroid_openssl_OpensslWrapper_genCert
  (JNIEnv *, jclass, jstring, jstring, jstring, jobject);

#ifdef __cplusplus
}
#endif
#endif
