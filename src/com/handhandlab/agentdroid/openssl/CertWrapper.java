package com.handhandlab.agentdroid.openssl;

public class CertWrapper {
	byte[] certBytes;
	byte[] keyBytes;
	public byte[] getCertBytes() {
		return certBytes;
	}
	public void setCertBytes(byte[] certBytes) {
		this.certBytes = certBytes;
	}
	public byte[] getKeyBytes() {
		return keyBytes;
	}
	public void setKeyBytes(byte[] keyBytes) {
		this.keyBytes = keyBytes;
	}
	
}
