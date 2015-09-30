#include <jni.h>

#include <malloc.h>
#include <android/log.h>
#include "com_handhandlab_openssltest_OpensslTest.h"
#include <stdio.h>
extern "C" {
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <agentdroid.h>
}

/**
 * test for openssl for base64
 */
void testBase64(const unsigned char* buffer, size_t length, char** b64text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = (*bufferPtr).data;
	int b64length = bufferPtr->length;
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "b64: %s %d", *b64text,
			b64length);
}

/**
 * test for openssl for generating certificate
 */
void generateKey() {
	X509 *x509;
	EVP_PKEY *privateKey;
	RSA *rsaKeyPair;
	X509_NAME *name = NULL;

	//create a key structure
	privateKey = EVP_PKEY_new();

	//generate a RSA key
	rsaKeyPair = RSA_generate_key(2048, /* number of bits for the key - 2048 is a sensible value */
	RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
	NULL, /* callback - can be NULL if we aren't displaying progress */
	NULL /* callback argument - not needed in this case */
	);

	EVP_PKEY_assign_RSA(privateKey, rsaKeyPair);

	//write to disk
	/* Open the PEM file for writing the key to disk. */
	FILE * pkey_file = fopen(
			"/data/data/com.handhandlab.openssltest/files/private_key.pem",
			"wb");

	/* Write the key to disk. */
	bool ret = PEM_write_PrivateKey(pkey_file, privateKey, NULL, NULL, 0, NULL,
			NULL);
	EVP_PKEY_free(privateKey);
	fclose(pkey_file);
}

EVP_PKEY* loadKey() {
	FILE * pkey_file = fopen(
			"/data/data/com.handhandlab.openssltest/files/private_key.pem",
			"r");
	EVP_PKEY *ca_pkey;

	//OpenSSL_add_all_algorithms();

	ca_pkey = EVP_PKEY_new();
	PEM_read_PrivateKey(pkey_file, &ca_pkey, NULL, NULL);

	fclose(pkey_file);
	return ca_pkey;
}

void testGenCertificate() {
	X509 *x509;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name = NULL;

	//create a key structure
	pk = EVP_PKEY_new();

	//generate a RSA key
	rsa = RSA_generate_key(2048, /* number of bits for the key - 2048 is a sensible value */
	RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
	NULL, /* callback - can be NULL if we aren't displaying progress */
	NULL /* callback argument - not needed in this case */
	);

	EVP_PKEY_assign_RSA(pk, rsa);

	//write key
	FILE * f;
	f = fopen("/data/data/com.handhandlab.openssltest/files/key.pem", "wb");
	PEM_write_PrivateKey(f, /* write the key to the file we've opened */
	pk, /* our key from earlier */
	EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
	(unsigned char*) "password", /* passphrase required for decrypting the key on disk */
	8, /* length of the passphrase string */
	NULL, /* callback for requesting a password */
	NULL /* data to pass to the callback */
	);

	//the cert itself
	x509 = X509_new();

	//set certificate attributes
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	//time
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	//set the public key
	X509_set_pubkey(x509, pk);
}

/**
 * test for openssl for AES
 */
void testAES() {

}

void Java_com_handhandlab_openssltest_OpensslTest_test(JNIEnv *env,
		jclass clazz, jstring jArg) {
	const unsigned char testData[4] = { 0x61, 0x62, 0x63, 0x00 };
	char* b64text;
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "b64");
	testBase64(testData, strlen((const char*) testData), &b64text);

	/*generateKey();
	 __android_log_print(ANDROID_LOG_DEBUG, "haha", "gen finish");
	 EVP_PKEY *pk = loadKey();


	 __android_log_print(ANDROID_LOG_DEBUG, "haha", "load finish");*/

	unsigned char isCopy;
	const char* filePathName = env->GetStringUTFChars(jArg, &isCopy);
	generateCA((const unsigned char*) filePathName);
	env->ReleaseStringUTFChars(jArg, filePathName);
}

jstring Java_com_handhandlab_openssltest_OpensslTest_generateCA(JNIEnv *env,
		jclass clazz, jstring folder) {
	unsigned char isCopy;
	const char* cFolder = env->GetStringUTFChars(folder, &isCopy);
	char* caName = generateCA((const unsigned char*) cFolder);
	env->ReleaseStringUTFChars(folder, cFolder);
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "generate CA finished %s",caName);
	jstring jCaName = env->NewStringUTF((const char*)caName);
	free(caName);
	return jCaName;
}

/*
 * Class:     com_handhandlab_openssltest_OpensslTest
 * Method:    generateCert
 * Signature: (Ljava/lang/String;)[B
 */
jbyteArray Java_com_handhandlab_openssltest_OpensslTest_generateCert(
		JNIEnv *env, jclass clazz, jstring folder, jstring cndomain,
		jstring sans, jobject certWrapper) {
	unsigned char isCopy;
	const char* cFolder = env->GetStringUTFChars(folder, &isCopy);
	const char* cDomain = env->GetStringUTFChars(cndomain, &isCopy);
	const char* cSans = env->GetStringUTFChars(sans, &isCopy);
	unsigned int len;
	unsigned char* keyBuf;
	int keyLen;
	unsigned char* buf = generateCert((const char*) cFolder,
			(const char*) cDomain, (const char*) cSans, &len, &keyBuf, &keyLen);

	// Get the class of the input object
	jclass certWrapperClass = env->GetObjectClass(certWrapper);

	// Get Method references
	jmethodID jmSetCertBytes = env->GetMethodID(certWrapperClass,"setCertBytes","([B)V");
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "check 1");
	jmethodID jmSetKeyBytes = env->GetMethodID(certWrapperClass,"setKeyBytes","([B)V");
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "check 2");

	jbyteArray ret = env->NewByteArray(len);
	env->SetByteArrayRegion(ret, 0, len, (const signed char*) buf);
	env->ReleaseStringUTFChars(folder, cFolder);
	env->ReleaseStringUTFChars(cndomain, cDomain);
	env->ReleaseStringUTFChars(sans, cSans);
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "check 3");
	// set key bytes buffer
	jbyteArray keyByteArray = env->NewByteArray(keyLen);
	env->SetByteArrayRegion(keyByteArray, 0, keyLen, (const signed char*) keyBuf);

	// Set fields for object
	//env->SetObjectField(certWrapperClass,certField, ret);
	env->CallVoidMethod(certWrapper,jmSetCertBytes,ret);
	env->CallVoidMethod(certWrapper,jmSetKeyBytes,keyByteArray);
	return ret;
}

jbyteArray Java_com_handhandlab_openssltest_OpensslTest_getKey(JNIEnv *env,
		jclass clazz, jstring folder) {
	unsigned char isCopy;
	const char* cFolder = env->GetStringUTFChars(folder, &isCopy);
	unsigned int len;
	unsigned char* buf = getKey((const char*) cFolder,&len);

	jbyteArray ret = env->NewByteArray(len);
	env->SetByteArrayRegion(ret, 0, len, (const signed char*) buf);
	env->ReleaseStringUTFChars(folder, cFolder);
	return ret;
}
