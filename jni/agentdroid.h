/**
 * generate CA
 * 1.write the CA certificate to /etc/security/cacerts/ with a hash name
 * 2.save the private key to @param priFolder + "prikey.pem"(full path)
 */
char* generateCA(const unsigned char* folder);

/**
 * generate a x509 certificate and sign it with the CA private key
 * @param priKeyLocation
 * @param domain
 * @param sans Must be in the format of "DNS.1:*.google.com,DNS.2:*.twitter.com,..."
 * @param keyBuf The private key bytes encoded in PKCS8 to be returned to Java
 * @param keyLen the length of the private key
 */
unsigned char* generateCert(const char* priKeyLocation,const char* domain,const char* sans,unsigned int* len,unsigned char** privateKeyBuf,int* keyLen);

unsigned char* getKey(const char* priKeyLocation, unsigned int* len);
