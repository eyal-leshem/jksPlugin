package Implemtor;

import java.io.IOException;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

public abstract class Implementor {
	
	protected String name;
	public Implementor() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * build the im
	 * 
	 * @param params - json string that contain parameters for this key Store 
	 * @throws Exception 
	 */
	public Implementor(String params) throws Exception {
		throw new Exception("unimplement"); 
	}
	
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public abstract Certificate genrateKeyPair(String dName) throws ImplementorExcption; 
	
	public abstract SecretKey   genrateSecertKey(String alg) throws ImplementorExcption; 
	
	public abstract boolean		installSecertKey(SecretKey key) throws ImplementorExcption ; 
	
	public abstract boolean		installTrustCert(Certificate cert) throws ImplementorExcption ;	
		
}
