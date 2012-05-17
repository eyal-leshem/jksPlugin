package Implemtor;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

public class JksImplemntor extends Implementor {
	         
   
    String ksPath; 
    String ksPassword; 
    MyKeyTool myKeyTool;
    File numAlias=new File("numAlias");
    
    
    public JksImplemntor(String params) throws  Exception {
    	
    	//TODO get from conf file
    	ksPath="a.keyStore";
    	ksPassword="a10097";
    	name="jks";
    	myKeyTool=new MyKeyTool(ksPath, "a10097");
    	myKeyTool.createNewKs();   
    	if(!numAlias.exists()){
    		numAlias.createNewFile(); 
    		FileWriter fw=new FileWriter(numAlias); 
    		fw.write("0001"); 
    		fw.flush(); 
    		fw.close(); 
    		
    	}
    		
		 
	}
	
	

	@Override
	public Certificate genrateKeyPair(String dName){
		try{
			String alias=null; 
			int numtry=0; 
			while(true){
				try{
					alias=getNextAlias(); 
					Certificate cert=myKeyTool.genartePrivatekey(alias, dName);
					return cert;
				}
				catch (KeyStoreException keyStore) {
					//may alias is catch for some reson 
					//try next
					if(numtry<1000){
						alias=getNextAlias(); 
						numtry++; 
					}
					else{
						throw keyStore; 
					}
				}
			}
		}
		catch (Exception e) {
			return null; 
		}
	    
		
	}

	private String getNextAlias() throws IOException {
	  FileReader fr=new FileReader(numAlias);
	  char[] numString=new char[4] ;
	  fr.read(numString);
	  fr.close(); 
	  
	  Integer num=new Integer(new String(numString)); 
	  String ans="alias"+num.toString();

	  writeNextToFile(num); 	    
	  return ans; 
	}



	@Override
	public SecretKey genrateSecertKey() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean installSecertKey(SecretKey key) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean installTrustCert(Certificate cert) {
		try{
			String alias=null; 
			int numtry=0; 
			while(true){
				try{
					alias=getNextAlias(); 
					myKeyTool.addTrustCert(cert, alias);
					return true;
				}
				catch (KeyStoreException keyStore) {
					//may alias is catch for some reson 
					//try next
					if(numtry<1000){
						alias=getNextAlias(); 
						numtry++; 
					}
					else{
						return false; 
					}
				}
			}
		}
		catch (Exception e) {
			return false; 
		}
		
		
	}
	
	private void writeNextToFile(Integer num) throws IOException{
		  num=new Integer(num.intValue()+1);
		  String numAliasString=num.toString(); 
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
		  
		  FileWriter fw=new FileWriter(numAlias);
		  fw.write(numAliasString);
		  fw.flush();
		  fw.close(); 
		
	}

}
