import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.hash.Sha512;
import gnu.crypto.hash.Whirlpool;


public class JSONSF_CryptoHash extends JSONSF_Crypto{

	public JSONSF_CryptoHash() {
		// TODO Auto-generated constructor stub
		super();
	}
	
	/**
	 * Whirlpool-T version of a byte buffer
	 * return a byte buffer encoded in base 64
	 */
	public  byte[] getWhirlpoolHash(byte[] input){
		Whirlpool whirlpool=new Whirlpool();
		whirlpool.update(input, 0, input.length);
		return (Base64Encode(whirlpool.digest())).getBytes();
	}
 
	/**
	 * Whirlpool-T version of a string
	 * return a ingstr encoded in base 64
	 */
	public String Hash_Whirlpool (String strToHash){
		
	     byte[] byteHash = {0};
		
	     IMessageDigest md_Whirlpool = HashFactory.getInstance("Whirlpool");
	     //MessageDigest md;
	     if (md_Whirlpool.selfTest()){
	    	 System.out.println("self test ok");
	    	 
	     }
	     byteHash = strToHash.getBytes();
	     md_Whirlpool.reset();
	     md_Whirlpool.update(byteHash, 0, byteHash.length);
	     
	     byteHash = md_Whirlpool.digest();
		
		return Base64Encode (byteHash);
		
	}
	
	/**
	 * Sha512 version of a string
	 * return a string encoded in base 64
	 */	
	// hash an input string and return the hash in a  string base 64 encoded
	public String Hash_Sha512 (String strToHash){
		
	     byte[] byteHash = {0};
		
	     IMessageDigest md_Sha512 = HashFactory.getInstance("Sha512");
	     byteHash = strToHash.getBytes();
	     md_Sha512.update(byteHash, 0, byteHash.length);
	     
	     byteHash = md_Sha512.digest();
		
		return Base64Encode (byteHash);
		
	}

	/**
	 * Sha512 version of a byte buffer
	 * return a byte buffer encoded in base 64
	 */	
	public  byte[] getSha512Hash(byte[] input){
		Sha512 sha512=new Sha512();
		sha512.update(input, 0, input.length);
		return (Base64Encode(sha512.digest())).getBytes();
	}
	

}
