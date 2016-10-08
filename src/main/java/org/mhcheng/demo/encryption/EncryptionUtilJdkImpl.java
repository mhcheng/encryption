package org.mhcheng.demo.encryption;

import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.codec.Hex;

public class EncryptionUtilJdkImpl implements EncryptionUtil {

	static final int PWD_ITERATIONS = 1024;
	static final int KEY_LENGTH = 256;
	static final int IV_KEYSIZE = 16;
	static final String SECRET_KEY_ALG = "PBKDF2WithHmacSHA1";
	static final String SECRET_KEY_SPEC_ALG = "AES";
	static final String CIPHER_ALG = "AES/CBC/PKCS5Padding";
	static final String ENCODING = "UTF-8";
	
	private static void test(String[] args) throws Exception {

		final String salt = "3b9297373e79778e";	// random 8 bytes using hex encoding
		/* 
		// random salt generation
		SecureRandom random = new SecureRandom(); 
		byte[] randomSaltBytes = new byte[8];
		random.nextBytes(randomSaltBytes);
		String randomSalt = new String(Hex.encode(randomSaltBytes));
		*/
	
		final String plainText = "This is a test message";
		final String password = "HelloWorld";
		
		int pswdIterations = PWD_ITERATIONS;
		int keySize = KEY_LENGTH;
		byte[] ivBytes;		
		
		//get salt
        byte[] saltBytes = Hex.decode(salt);
         
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALG);
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
                );
 
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), SECRET_KEY_SPEC_ALG);
 
        //encrypt the message
        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        
        System.out.println(Hex.encode(ivBytes));
        
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes(ENCODING));
        System.out.println(Hex.encode(encryptedTextBytes));
		
	}

	private Cipher getCipher(int encryptMode, String salt, String password, AlgorithmParameterSpec paramSpec) throws Exception {
		
		// decode salt
		byte[] saltBytes = Hex.decode(salt);
		
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                PWD_ITERATIONS, 
                KEY_LENGTH
                );
        
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        if (paramSpec == null) {
        	cipher.init(encryptMode, secret);
        } else {
        	cipher.init(encryptMode, secret, paramSpec);
        }
        
		return cipher;
	}


	public String encrypt(String plainText, String salt, String password) throws Exception {

		Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, salt, password, null);
        AlgorithmParameters params = cipher.getParameters();
        // ivBytes
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        // encrypt plainText to get cipherBytes
        byte[] cipherBytes = cipher.doFinal(plainText.getBytes(ENCODING));
             
        // concat ivBytes and cipherBytes to form encryptedBytes
        byte[] encryptedBytes = new byte[ivBytes.length + cipherBytes.length];
        System.arraycopy(ivBytes, 0, encryptedBytes, 0, ivBytes.length);
        System.arraycopy(cipherBytes, 0, encryptedBytes, ivBytes.length, cipherBytes.length);
        
        // hex encode encryptedBytes
        return new String(Hex.encode(encryptedBytes));
        
	}

	public String decrypt(String cipherText, String salt, String password) throws Exception {
		
		// hex decode encryptedBytes
		byte[] encryptedBytes = Hex.decode(cipherText);
        
		// extract ivBytes and cipherBytes
        byte[] ivBytes = new byte[IV_KEYSIZE];
        byte[] cipherBytes = new byte[encryptedBytes.length - IV_KEYSIZE];
        System.arraycopy(encryptedBytes, 0, ivBytes, 0, IV_KEYSIZE);
        System.arraycopy(encryptedBytes, IV_KEYSIZE, cipherBytes, 0, encryptedBytes.length - IV_KEYSIZE);
        
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, salt, password, new IvParameterSpec(ivBytes));
        
        // decrypt cipher to get original text
        return new String(cipher.doFinal(cipherBytes), ENCODING);
		
	}

}
