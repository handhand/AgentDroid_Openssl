#include <jni.h>
#include <android/log.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "agentdroid.h"

#define C (unsigned char *)"CN"
#define OU (unsigned char *)"AgentDroid"
#define O (unsigned char *)"Handhand Lab"
#define CN (unsigned char *)"handhandlab.com"

/*
 * Add extension using V3 code: we can set the config file as NULL because we
 * wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/*
	 * Issuer and subject certs: both the target since it is self signed, no
	 * request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}


/**
 * Load the CA private key from disk
 */
EVP_PKEY* loadCAKey(const unsigned char* priFolder) {
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "loadCAKey, priFolder:%s",
			priFolder);
	unsigned char priKeyFile[80] = "";
	strcpy(priKeyFile, priFolder);
	strcat(priKeyFile, "prikey.pem");

	__android_log_print(ANDROID_LOG_DEBUG, "haha", "private key file name:%s",
			priKeyFile);
	FILE * pkey_file = fopen(priKeyFile, "r");
	EVP_PKEY *ca_pkey;

	//OpenSSL_add_all_algorithms();

	ca_pkey = EVP_PKEY_new();
	PEM_read_PrivateKey(pkey_file, &ca_pkey, NULL, NULL);

	fclose(pkey_file);
	return ca_pkey;
}

/**
 * generate CA
 * 1.write the CA certificate to /etc/security/cacerts/ with a hash name
 * 2.save the private key to @param priFolder + "prikey.pem"(full path)
 */
char* generateCA(const unsigned char* priFolder) {
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "generate ca folder:%s",
			priFolder);
	X509 *x509;
	EVP_PKEY *privateKey;
	RSA *rsaKeyPair;
	X509_NAME *name = NULL;

	//------------generate a key pair for CA first-----------
	//the private key will sign the CA, and sign other certificate

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
	char priKeyFileFull[80] = "";
	strcat(priKeyFileFull, priFolder);
	strcat(priKeyFileFull, "prikey.pem");
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "key file:%s",
			priKeyFileFull);

	FILE * pkey_file = fopen(priKeyFileFull, "wb");

	/* Write the key to disk. */
	PEM_write_PrivateKey(pkey_file, privateKey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "write finish");
	//---------------generate the CA certificate-----------------------------
	x509 = X509_new();

	//set certificate attributes
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	//time
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L + 60 * 60 * 24 * 365 * 5);
	//set the public key
	X509_set_pubkey(x509, privateKey);

	//issuer info,TODO:this might be wrong!!!!!!!!!!!!!!
	name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, CN, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, OU, -1, -1, 0);

	//set issuer, who issue this cert (itself, so subject and issuer are the same)
	X509_set_issuer_name(x509, name);

	/* Add various extensions: standard extensions */
	add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x509, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(x509, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	add_ext(x509, NID_netscape_cert_type, "sslCA");

	add_ext(x509, NID_netscape_comment, "agentdroid");

	//sign the X509 certificate with the private key
	X509_sign(x509, privateKey, EVP_sha1());

	//get the subject hash to be the hash name (android specs)
	unsigned long hash = X509_subject_name_hash_old(x509);
	unsigned char caHashName[30] = "";
	sprintf(caHashName, "%lx.0", hash);

	//save the ca file to app folder
	unsigned char caFileNameFull[80] = "";
	strcat(caFileNameFull, priFolder);
	strcat(caFileNameFull, caHashName);
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "hashName:%s",caHashName);
	FILE * f;
	f = fopen(caFileNameFull, "wb");
	PEM_write_X509(f, /* write the certificate to the file we've opened */
	x509 /* our certificate */
	);
	fclose(f);

	//leave the following to java site
	//copy the ca file to system folder
	/*char cmd[200] = "";
	strcat(cmd, "su -c \"mount -o remount,rw /system; cat ");
	strcat(cmd, caFileNameFull);
	strcat(cmd, " > /etc/security/cacerts/");
	strcat(cmd, caHashName);
	strcat(cmd, "\"");
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "cmd:%s", cmd);
	system(cmd);*/

	EVP_PKEY_free(privateKey);

	char* retCaName = malloc(strlen(caHashName)+1);
	strcpy(retCaName,caHashName);
	return retCaName;
}

/**
 * generate a x509 certificate and sign it with the CA private key
 * @param priKeyLocation
 * @param domain
 * @param sans Must be in the format of "DNS.1:*.google.com,DNS.2:*.twitter.com,..."
 * @param keyBuf The private key bytes encoded in PKCS8 to be returned to Java
 * @param keyLen the length of the private key
 */
unsigned char* generateCert(const char* priKeyLocation, const char* domain,
		const char* sans, unsigned int* len,unsigned char** keyBuf,int* keyLen) {
	__android_log_print(ANDROID_LOG_DEBUG, "haha","start native generate cert,priKeyLocation:%s", priKeyLocation);
	X509 *x509;
	EVP_PKEY *privateKey;
	RSA *rsaKeyPair;
	X509_NAME *subjectName = NULL;

	//------------generate a key pair-----------
	//create a key structure
	privateKey = EVP_PKEY_new();

	//generate a RSA key
	rsaKeyPair = RSA_generate_key(2048, /* number of bits for the key - 2048 is a sensible value */
	RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
	NULL, /* callback - can be NULL if we aren't displaying progress */
	NULL /* callback argument - not needed in this case */
	);

	EVP_PKEY_assign_RSA(privateKey, rsaKeyPair);

	//-----------convert the cert's private key to PKCS8 and set it to buffer
	BUF_MEM *bufferPtr;
	BIO *bp = BIO_new(BIO_s_mem());
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "start transfer to PKCS8");
	i2d_PKCS8PrivateKey_bio(bp, privateKey, NULL,NULL, 0,NULL, NULL);

	BIO_get_mem_ptr(bp, &bufferPtr);
	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free_all(bp);
	*keyLen = bufferPtr->length;
	*keyBuf = (*bufferPtr).data;

	__android_log_print(ANDROID_LOG_DEBUG, "haha", "start load key");
	//---------------load the CA private key-----------------
	EVP_PKEY *caKey = loadCAKey(priKeyLocation);
	__android_log_print(ANDROID_LOG_DEBUG, "haha",
			"finish native generate cert");

	//---------------generate the certificate-----------------------------
	x509 = X509_new();

	//set certificate attributes
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	//time
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	//set the public key
	X509_set_pubkey(x509, privateKey);

	//subject info
	subjectName = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(subjectName, "C", MBSTRING_ASC, C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subjectName, "O", MBSTRING_ASC, O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, domain, -1, -1,
			0);

	__android_log_print(ANDROID_LOG_DEBUG, "haha", "start set issuer");
	//set issuer, who issue this cert
	X509_NAME *issuerName = X509_NAME_new();
	//same with the CA
	X509_NAME_add_entry_by_txt(issuerName, "C", MBSTRING_ASC, C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuerName, "O", MBSTRING_ASC, O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC, CN, -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuerName, "OU", MBSTRING_ASC, OU, -1, -1, 0);
	X509_set_issuer_name(x509, issuerName);

	//------------set subject alternative names---------------
	add_ext(x509, NID_subject_alt_name, sans);

	//sign the X509 certificate with the CA private key loaded in previous step
	X509_sign(x509, caKey, EVP_sha1());

	//------------parse the x509 to bytes and pass it to java---------------
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "start i2d ");
	unsigned char *buf;
	buf = NULL;
	*len = i2d_X509(x509, &buf);
	return buf;
}

/**
 * java needs the key to be PKCS8 encoded
 */
unsigned char* getKey(const char* priKeyLocation, unsigned int* len){
	EVP_PKEY *caKey = loadCAKey(priKeyLocation);
	BUF_MEM *bufferPtr;
	BIO *bp = BIO_new(BIO_s_mem());
	__android_log_print(ANDROID_LOG_DEBUG, "haha", "start transfer to PKCS8");
	i2d_PKCS8PrivateKey_bio(bp, caKey, NULL,NULL, 0,NULL, NULL);

	BIO_get_mem_ptr(bp, &bufferPtr);
	BIO_set_close(bp, BIO_NOCLOSE);
	BIO_free_all(bp);
	*len = bufferPtr->length;
	return (*bufferPtr).data;
}
