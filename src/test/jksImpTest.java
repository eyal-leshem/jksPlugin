package test;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import Implemtor.Implementor;
import Implemtor.ImplementorExcption;
import Implemtor.JksImplemntor;
import MykeyTool.MyKeyToolException;

public class jksImpTest {
	
	JSONObject conf; 
	
	String lock=new String(); 
	
	BigInteger serial=null; 

@Test
public void creationOfSecretKey(){
		
			
		Implementor imp=loadImp(); 
		
		SecretKey key = null;
		try {
			key=imp.genrateSecertKey("AES","a");
		} catch (ImplementorExcption e) {
			fail("can't create aes key"); 
		} 
		
		KeyStore ks = null; 
		try {
			ks=loadKeyStore();
		} catch (Exception e) {
			fail("can't load the keystore"); 
		}
		
		SecretKey secKey=null; 
		try {
			secKey=(SecretKey) ks.getKey("a", conf.getString("ksPassword").toCharArray());
		} catch (Exception e) {
			fail("can't get the key from the key store"); 			
		} 
		
		assertEquals(key,secKey); 
		
		
		

	
		
	}
	
@Test
public void savingSecertKey(){
	
	KeyGenerator keyGen = null;
	try {
		keyGen = KeyGenerator.getInstance("AES");
	} catch (NoSuchAlgorithmException e) {
		fail("can't generate key"); 
	} 
	
	SecretKey 	 key=keyGen.generateKey();
	
	Implementor imp=loadImp();
	
	try {
		imp.installSecertKey(key,"b");
	} catch (ImplementorExcption e) {
		fail("can't insatll the privtae key");
	}
	
	KeyStore ks = null; 
	try {
		ks=loadKeyStore();
	} catch (Exception e) {
		fail("can't load the keystore"); 
	}
	
	SecretKey secKey=null; 
	try {
		secKey=(SecretKey) ks.getKey("b", conf.getString("ksPassword").toCharArray());
	} catch (Exception e) {
		fail("can't get the key from the key store"); 			
	} 
	
	assertEquals(key,secKey); 
	
	
	
}

@Test
public void genrateCertificate(){
	synchronized (lock) {

		Implementor imp=loadImp(); 
		
		Certificate cert=null;
		try {
			cert= imp.genrateKeyPair("cn=a", "c");
		} catch (ImplementorExcption e) {
			fail("can't genarate a key pair"); 
		} 
		
		KeyStore ks = null; 
		try {
			ks=loadKeyStore();
		} catch (Exception e) {
			fail("can't load the keystore"); 
		}
		
		Certificate cert2=null;
		try {
			cert2=ks.getCertificate("c");
		} catch (KeyStoreException e) {
			fail("plobelm to use the key store"); 
		} 
		
		assertEquals(cert,cert2); 
		
		serial=((X509Certificate)cert).getSerialNumber(); 
	}
	
}

@Test
public void removeCertificate(){
	Implementor imp=loadImp(); 
	
	genrateCertificate();
	
	synchronized (lock) {	
	
		try {
			imp.removeCertificate(serial);
		} catch (ImplementorExcption e) {
			fail("can't remove the certificate");
		} 
		
		KeyStore ks = null; 
		try {
			ks=loadKeyStore();
		} catch (Exception e) {
			fail("can't load the keystore"); 
		}
		
		try {
			assertFalse(ks.containsAlias("c"));
		} catch (KeyStoreException e) {
			fail("problem with keystore"); 
		} 
	}
	
	
	
}




private Implementor loadImp(){
	
	String jsonConf = null;
	try{
		File f=new File("conf.cnf"); 
		char[] buffer=new char[(int)f.length()]; 
		FileReader fr= new FileReader(f);
		fr.read(buffer);
		jsonConf=new String(buffer); 
		conf=new JSONObject(jsonConf); 
	}
	catch(Exception e){
		fail("poblem to load conf file"); 
	}
	
	Implementor imp = null; 
	try {
		imp=new JksImplemntor(jsonConf);
	} catch (Exception e) {
		fail("problem to load the implemntor"); 
	}
	
	return imp; 
	
}


private  KeyStore loadKeyStore() throws  Exception {
		
		InputStream instream = null;
		KeyStore keyStore;
		
		String	ksPassword=conf.getString("ksPassword"); 
    	String	ksPath=conf.getString("ksPath");
		
		try{
			keyStore = KeyStore.getInstance("JCEKS");	 		
			instream = new FileInputStream(new File(ksPath));  
			keyStore.load(instream, ksPassword.toCharArray());
		
           } 
			catch (Exception e) {
			 throw e; 
			}
			finally {
               try { instream.close(); } catch (Exception ignore) {  }
           }
           return keyStore; 
	}

	


}
