package Implemtor;

import java.io.IOException;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

public abstract class Implementor {
	
	protected String name;
	public Implementor() {
		// TODO Auto-generated constructor stub
	}
	
	public Implementor(String params) {
		// TODO Auto-generated constructor stub
	}
	
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public abstract Certificate genrateKeyPair(String dName); 
	
	public abstract SecretKey   genrateSecertKey(); 
	
	public abstract boolean		installSecertKey(SecretKey key); 
	
	public abstract boolean		installTrustCert(Certificate cert) ;	
		
}
