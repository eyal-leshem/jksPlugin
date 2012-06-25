package Implemtor;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import mjson.*;

import sun.applet.Main;


import javax.crypto.SecretKey;

import MykeyTool.MyKeyTool;
import MykeyTool.MyKeyToolBaseExctpion;
import MykeyTool.MyKeyToolConf;
import MykeyTool.MyKeyToolException;
import MykeyTool.MykeyToolIoException;

public class JksImplemntor extends Implementor {
	         
   
    String ksPath; 
    String ksPassword; 
    MyKeyTool myKeyTool;
    File numAlias=new File("numAlias");
    
    
    public JksImplemntor(String params) throws  Exception {
    	
    	//get the parameters of the implementor 
    	//that encoded in json 
    	Json json=Json.read(params);
    	ksPassword=(String)json.at("password").getValue(); 
    	ksPath=(String)json.at("keyStorePath").getValue();
    	
    	//set the name of this implementor 
    	//the default is "Jksimplemntor" 
    	if(json.at("name")==null) 
    		name="JksImplemntor";
    	else 
    		name=(String)json.at("name").getValue(); 
    	
    	//Configure the key tool (use key store type jceks- for saving private keys); 
    	MyKeyToolConf conf=new MyKeyToolConf(ksPath, "a10097"); 
    	conf.setKeyStoreType("JCEKS");
    	
    	//create new keytool object and new keystore 
    	myKeyTool=new MyKeyTool(conf);
    	myKeyTool.createNewKs();   
    	
    	//numAlias is a file that contain number 
    	//this number use to give alias name (like: "alias1" "alias2" ..) 
    	//when we generate new keystore entry we will increment this number 
    	if(!numAlias.exists()){
    		numAlias.createNewFile(); 
    		FileWriter fw=new FileWriter(numAlias); 
    		fw.write("0001"); 
    		fw.flush(); 
    		fw.close(); 
    		
    	}
    		
		 
	}
	
	

	@Override
	public Certificate genrateKeyPair(String dName,String alias) throws ImplementorExcption{
		try{
			
			
			//genrate cert 
			Certificate cert=myKeyTool.genartePrivatekey(alias, dName);
			return cert;
			
		}
		catch (Exception e) {
			throw new ImplementorExcption("can't genarte the key",e);  
		}	
	}
	
	/*
	 * return the next alias from the file 
	 */
	private String getNextAlias() throws IOException {
	  //read nem from file  
	  FileReader fr=new FileReader(numAlias);
	  char[] numString=new char[4] ;
	  fr.read(numString);
	  fr.close(); 
	  
	  //return the new alias strig 
	  Integer num=new Integer(new String(numString)); 
	  String ans="alias"+num.toString();

	  //write the next alias to the file 
	  writeNextToFile(new Integer(num.intValue()+1)); 	    
	  return ans; 
	}



	@Override
	public SecretKey genrateSecertKey(String alg) throws ImplementorExcption {
		SecretKey key; 
		try {
			key=myKeyTool.genrateSecretKey(getNextAlias(), alg);
		} catch (MyKeyToolBaseExctpion e){
			throw new ImplementorExcption("problem to genrate the key", e) ; 
		} catch (IOException e) {
			throw new ImplementorExcption("problem to genarte the alias", e);
		} 
		
		return key;
	}

	@Override
	public boolean installSecertKey(SecretKey key) throws ImplementorExcption {
		//try to add the secret key 
		try{
			myKeyTool.addSecretKey(key,getNextAlias()); 
		}
		catch (Exception e) {
			throw new ImplementorExcption("problem to store the key in the keyStore", e) ; 
		}
		return true;
	}

	@Override
	public boolean installTrustCert(Certificate cert) {
		try{
			String alias=getNextAlias(); 
			while(myKeyTool.containAlias(alias)){
				alias=getNextAlias(); 
			}
			
			myKeyTool.addTrustCert(cert, alias);
			return true;
			
		}
		catch (Exception e) {
			return true; 
		}
		
		
	}
	/*
	 * write the nember to the file in 4 digits 
	 */
	private void writeNextToFile(Integer num) throws IOException{
		  num=new Integer(num.intValue()+1);
		  String numAliasString=num.toString(); 
		  //make it 4 digits 
		  switch (numAliasString.length()){
		  	case 1:
		  		numAliasString="000"+numAliasString; 
		  		break;
		  	case 2: 
		  		numAliasString="00"+numAliasString; 
		  		break; 
		  	case 3: 
		  		numAliasString="0"+numAliasString; 
		  		break; 
		  	case 5:
		  		numAliasString="0000"+numAliasString; 
		  		break;
		  	default:
		  		break;
		  }
		  //write it to the file 
		  FileWriter fw=new FileWriter(numAlias);
		  fw.write(numAliasString);
		  fw.flush();
		  fw.close(); 
		
	}
	
	public static void main(String[] argv) throws Exception{
		Implementor imp=new JksImplemntor("{\"keyStorePath\":\"C:\\temp\\keyStore\\my.keyStore\",\"password\":\"a10097\"}");
		imp.genrateSecertKey("AES"); 
	}

}
