package org.mhcheng.demo.encryption;

public interface EncryptionUtil {

	public String encrypt(String planText, String salt, String password) throws Exception;
	public String decrypt(String cipher, String salt, String password) throws Exception;
	
}
