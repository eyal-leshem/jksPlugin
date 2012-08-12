package Implemtor;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import mjson.Json;

import MykeyTool.*;


public class JksImplemntor extends Implementor {
	    
	public final String  defulatStoreType="JCEKS"; 
	public final String  defulatImpName="keyStoreImplementor"; 
   
    String ksPath; 
    String ksPassword; 
    String ksType; 
    
    
    String tsPath; 
    String tsPassword; 
    String tsType;
  
    
    
    MyKeyTool ksKeyTool;
    MyKeyTool tsKeyTool; 
    
    String algs; 
    
    
    
    File numAlias=new File("numAlias");
    
    
    public JksImplemntor(String params) throws  Exception {
    	
    	/*get the parameters of the implementor 
    	that encoded in json */
    	
    	//read from json  
    	Json json=Json.read(params);
    	
    	//get ks params 
    	ksPassword=(String)json.at("ksPassword").getValue(); 
    	ksPath=(String)json.at("ksPath").getValue();
    	
    	
    	//get the trust store parms 
    	tsPassword=(String)json.at("tsPassword").getValue(); 
    	tsPath=(String)json.at("tsPath").getValue();    	
    	
    	
    	//get the algorithem 
    	algs=(String)json.at("algs").getValue(); 
    	    	
    	//set the name of this implementor 
    	//the default is "Jksimplemntor" 
    	if(json.at("name")==null) 
    		name="defulatImpName";
    	else 
    		name=(String)json.at("name").getValue(); 
    	
    	
    	//get type of keystore 
    	if(json.at("ksType")==null)
    		this.ksType=defulatStoreType; 
    	else
    		this.ksType=(String)json.at("ksType").getValue(); 
    	
    	//get type of trust sotre 
    	//case no proprty ane such trustsote we assume that is the same type of keystore 
    	if(json.at("tsType")==null)
    		this.tsType=this.tsType; 
    	else
    		this.tsType=(String)json.at("tsType").getValue();
    	    	
    	
    	//load the trust store  
    	
    	//Configure the key tool (use key store type jceks- for saving private keys); 
    	MyKeyToolConf ksconf=new MyKeyToolConf(ksPath, ksPassword); 
    	ksconf.setKeyStoreType(ksType);
    	
    	//create new keytool object and new keystore 
    	ksKeyTool=new MyKeyTool(ksconf);
    	if(!(new File(ksPath).exists()))
    		ksKeyTool.createNewKs();   
    	
    	//create the truststore  -
    	
    	//Configure the key tool (use key store type jceks- for saving private keys); 
    	MyKeyToolConf tsconf=new MyKeyToolConf(tsPath, tsPassword); 
    	tsconf.setKeyStoreType(tsType);
    	
    	//create new keytool object and new keystore 
    	tsKeyTool=new MyKeyTool(tsconf);
    	if(!(new File(tsPath).exists()))
    		tsKeyTool.createNewKs();
    	

    		
		 
	}
	
	

	@Override
	public Certificate genrateKeyPair(String dName,String alias) throws ImplementorExcption{
		try{
			
			//Generate certificate  
			Certificate cert=ksKeyTool.genartePrivatekey(alias, dName);
			return cert;
			
		}
		catch (Exception e) {
			throw new ImplementorExcption("can't genarte the key",e);  
		}	
	}
	



	@Override
	public SecretKey genrateSecertKey(String alg,String alias) throws ImplementorExcption {
		SecretKey key; 
		try {
			key=ksKeyTool.genrateSecretKey(alias, alg);
		} catch (MyKeyToolBaseExctpion e){
			throw new ImplementorExcption("problem to genrate the key", e) ; 
		} 
		
		return key;
	}

	@Override
	public boolean installSecertKey(SecretKey key,String alias) throws ImplementorExcption {
		//try to add the secret key 
		try{
			tsKeyTool.addSecretKey(key,alias); 
		}
		catch (Exception e) {
			throw new ImplementorExcption("problem to store the key in the keyStore", e) ; 
		}
		return true;
	}

	@Override
	public boolean installTrustCert(Certificate cert,String alias) {
		try{					
			
			tsKeyTool.addTrustCert(cert, alias);
			return true;
			
		}
		catch (Exception e) {
			return true; 
		}
		
		
	}
	
	@Override
	public boolean removeCertificate(BigInteger serialNumber)
			throws ImplementorExcption {
		
		try{
			ksKeyTool.deleteFromks(serialNumber); 
			tsKeyTool.deleteFromks(serialNumber); 
		}catch (MyKeyToolBaseExctpion e) {
			throw new ImplementorExcption("can't delete certifcate with serail number "+serialNumber+"from key store",e);
		}
		
		return true; 
	}
	
	@Override
	public ArrayList<String> getAlgorithms()
	{
		String[] arr=algs.split(",");
		
		ArrayList<String> toReturn=new ArrayList<String>(); 
		
		for(int i=0;i<arr.length;i++){
			toReturn.add(arr[i]); 
		}
		
		return toReturn;
	
		
	}
	
	

	public static void main(String[] argv) throws Exception{
		
		File f=new File("conf.cnf"); 
		char[] buffer=new char[(int)f.length()]; 
		FileReader fr= new FileReader(f);
		fr.read(buffer);
		String jsonConf=new String(buffer); 
		
		Implementor imp=new JksImplemntor(jsonConf);
		 ArrayList<String> alg= imp.getAlgorithms();
		
		imp.genrateSecertKey("AES","3");
		Certificate cert=imp.genrateKeyPair("CN=a","c"); 
		//imp.installTrustCert(cert, "b"); 
		imp.removeCertificate(((X509Certificate)cert).getSerialNumber()); 
		
	}
	
	

}
