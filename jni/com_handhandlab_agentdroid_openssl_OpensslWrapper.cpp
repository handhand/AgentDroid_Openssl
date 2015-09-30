#include <jni.h>
#include <android/log.h>
#include "com_handhandlab_agentdroid_openssl_OpensslWrapper.h"
extern "C"{
#include "agentdroid.h"
}
jstring Java_com_handhandlab_agentdroid_openssl_OpensslWrapper_genCA
  (JNIEnv *env, jclass clazz, jstring folder){
	unsigned char isCopy;
	const char* cFolder = env->GetStringUTFChars(folder,&isCopy);
	const char* caName = (const char*)generateCA((const unsigned char*)cFolder);
	env->ReleaseStringUTFChars(folder,cFolder);
	jstring jCaName = env->NewStringUTF(caName);
	__android_log_print(ANDROID_LOG_DEBUG,"haha","generate CA finished");
	return jCaName;
}

jbyteArray Java_com_handhandlab_agentdroid_openssl_OpensslWrapper_genCert
  (JNIEnv * env, jclass clazz, jstring priFolder, jstring domain, jstring sans, jobject certWrapper){
	unsigned char isCopy;
	const char* cFolder = env->GetStringUTFChars(priFolder,&isCopy);
	const char* cDomain = env->GetStringUTFChars(domain,&isCopy);
	const char* cSans = env->GetStringUTFChars(sans,&isCopy);
	unsigned int len;
	int keyLen;
	unsigned char* keyBuf;
	unsigned char* buf = generateCert(
				(const char*)cFolder,
				(const char*)cDomain,
				(const char*)cSans,
				&len,
				&keyBuf,
				&keyLen);

	// Get the class of the input object
	jclass certWrapperClass = env->GetObjectClass(certWrapper);

	// Get Method references
	jmethodID jmSetCertBytes = env->GetMethodID(certWrapperClass,"setCertBytes","([B)V");
	jmethodID jmSetKeyBytes = env->GetMethodID(certWrapperClass,"setKeyBytes","([B)V");

	// set key bytes buffer
	jbyteArray keyByteArray = env->NewByteArray(keyLen);
	env->SetByteArrayRegion(keyByteArray, 0, keyLen, (const signed char*) keyBuf);
	env->CallVoidMethod(certWrapper,jmSetKeyBytes,keyByteArray);

	//set cert bytes buffer
	jbyteArray certByteArray = env->NewByteArray(len);
	env->SetByteArrayRegion(certByteArray,0,len,(const signed char*)buf);
	env->CallVoidMethod(certWrapper,jmSetCertBytes,certByteArray);

	//release resources
	env->ReleaseStringUTFChars(priFolder,cFolder);
	env->ReleaseStringUTFChars(domain,cDomain);
	env->ReleaseStringUTFChars(sans,cSans);
	return certByteArray;
}
