package com.handhandlab.openssltest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import android.content.Context;
import android.util.Log;

import com.handhandlab.agentdroid.openssl.CertWrapper;

public class OpensslTest {
	public static native void test(String arg);
	
	/**
	 * @param priFolder where the private key of the CA will be stored
	 */
	public static native String generateCA(String priFolder);
	
	/**
	 * @param folder where the private key of the CA is stored
	 * @param domain domain name used in CN
	 * @param sans
	 * @return DER encoded byte array
	 */
	public static native byte[] generateCert(String folder,String CNDomain,String sans,CertWrapper certWrapper);
	
	public static native byte[] getKey(String folder);
	
	public static X509Certificate ttt(Context context){
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			File folder = context.getDir("secret", 0);
			Log.d("haha", "folder:"+folder.getAbsolutePath());
			CertWrapper certWrapper = new CertWrapper();
			InputStream in = new ByteArrayInputStream(generateCert("/data/data/com.handhandlab.openssltest/","www.google.com.hk","DNS.1:*.google.com,DNS.2:*.twitter.com",certWrapper));
			InputStream in2 = new ByteArrayInputStream(certWrapper.getCertBytes());
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in2);
			Log.d("haha", cert.getSigAlgName()+" "+cert.getIssuerDN()+" "+cert.getSubjectDN());
			checkHostname(cert);
			
			byte[] keydata = getKey("/data/data/com.handhandlab.openssltest/");
			KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
			PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(certWrapper.getKeyBytes()));
			Log.d("haha", "check key:"+privateKey.getAlgorithm()+" "+privateKey.getFormat());
			return cert;
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static void checkHostname(X509Certificate cert) throws CertificateParsingException{
		Log.d("haha", "san size:"+cert.getSubjectAlternativeNames().size());
		for(List list:cert.getSubjectAlternativeNames()){
			Log.d("haha", "list size:"+list.size());
			Log.d("haha", "this should be type:"+list.get(0));
			Log.d("haha", "this should be the value:"+list.get(1));
		}
	}
}
